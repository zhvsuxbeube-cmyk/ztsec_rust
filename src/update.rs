use std::{
    ffi::{OsString, OsStr},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use crate::telemetry;

const MAX_UPDATE_BYTES: usize = 64 * 1024 * 1024;
const SUCCESSOR_FLAG: &str = "--ztsec-update-successor";
const PROBE_FLAG: &str = "--ztsec-update-probe";
const SOURCE_ARG: &str = "--ztsec-update-source=";
const TARGET_ARG: &str = "--ztsec-update-target=";
const HASH_ARG: &str = "--ztsec-update-hash=";
const PARENT_ARG: &str = "--ztsec-update-parent=";
const LAUNCH_ARG: &str = "--ztsec-update-agent-arg=";
const SERVER_IP_ARG: &str = "--ztsec-update-server-ip=";
const SERVER_PORT_ARG: &str = "--ztsec-update-server-port=";
const HANDOFF_PORT_ARG: &str = "--ztsec-update-handoff-port=";
const HANDOFF_TOKEN_ARG: &str = "--ztsec-update-handoff-token=";
const FINGERPRINT_ARG: &str = "--ztsec-update-fingerprint=";

const PROBE_WAIT: Duration = Duration::from_secs(45);
const CHILD_WAIT: Duration = Duration::from_secs(45);
const PARENT_WAIT: Duration = Duration::from_secs(120);
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const PROBE_READ_TIMEOUT: Duration = Duration::from_secs(15);
const HANDOFF_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const HANDOFF_READ_TIMEOUT: Duration = Duration::from_secs(5);
const REPLACEMENT_RETRIES: usize = 40;
const REPLACEMENT_RETRY_DELAY: Duration = Duration::from_millis(250);

const PROBE_HELLO_PREFIX: &str = "HELLO:UPDATE-PROBE:";
const PROBE_ACK_PREFIX: &str = "ACK:UPDATE-PROBE:";
const PROBE_READY_PREFIX: &str = "UPDATE_PROBE_READY:";
const PROBE_READY_ACK_PREFIX: &str = "ACK:UPDATE_PROBE_READY:";
const PROBE_FAILED_PREFIX: &str = "UPDATE_PROBE_FAILED:";

pub(crate) fn max_update_bytes() -> usize {
    MAX_UPDATE_BYTES
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn validate_hash(expected: &str, actual: &str) -> bool {
    let expected = expected.trim();
    expected.len() == 64
        && expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        && expected.eq_ignore_ascii_case(actual)
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let compact: Vec<u8> = input
        .bytes()
        .filter(|byte| !matches!(byte, b'\r' | b'\n' | b'\t' | b' '))
        .collect();

    if compact.is_empty()
        || compact.len() > MAX_UPDATE_BYTES.saturating_mul(4) / 3 + 4
        || compact.len() % 4 == 1
    {
        return None;
    }

    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let has_full_padding_boundary = compact.len() % 4 == 0;
    let mut output = Vec::with_capacity(compact.len() * 3 / 4);
    let mut index = 0;

    while index < compact.len() {
        let remaining = compact.len() - index;
        if remaining >= 4 {
            let a = value(compact[index])? as u32;
            let b = value(compact[index + 1])? as u32;
            let pad_second = compact[index + 2] == b'=';
            let pad_third = compact[index + 3] == b'=';
            let c = if pad_second {
                0
            } else {
                value(compact[index + 2])? as u32
            };
            let d = if pad_third {
                0
            } else {
                value(compact[index + 3])? as u32
            };

            if (pad_second && !pad_third)
                || (pad_second || pad_third) && index + 4 != compact.len()
            {
                return None;
            }
            if pad_second && (b & 0x0f) != 0 {
                return None;
            }
            if pad_third && !pad_second && (c & 0x03) != 0 {
                return None;
            }

            output.push(((a << 2) | (b >> 4)) as u8);
            if !pad_second {
                output.push(((b << 4) | (c >> 2)) as u8);
            }
            if !pad_third {
                output.push(((c << 6) | d) as u8);
            }
            index += 4;
        } else {
            if has_full_padding_boundary {
                return None;
            }

            let a = value(compact[index])? as u32;
            let b = value(compact[index + 1])? as u32;
            output.push(((a << 2) | (b >> 4)) as u8);

            if remaining == 3 {
                let c = value(compact[index + 2])? as u32;
                if (c & 0x03) != 0 {
                    return None;
                }
                output.push(((b << 4) | (c >> 2)) as u8);
            } else if (b & 0x0f) != 0 {
                return None;
            }
            index = compact.len();
        }
    }

    if output.is_empty() || output.len() > MAX_UPDATE_BYTES {
        None
    } else {
        Some(output)
    }
}

pub(crate) fn stage_bytes(bytes: &[u8], expected_hash: &str) -> io::Result<PathBuf> {
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "update payload is empty",
        ));
    }
    if bytes.len() > MAX_UPDATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "update payload is too large",
        ));
    }

    let actual_hash = sha256_hex(bytes);
    if !validate_hash(expected_hash, &actual_hash) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "update hash mismatch",
        ));
    }

    let staged_path = tempfile_path();
    let mut handle = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staged_path)?;

    if let Err(error) = handle.write_all(bytes).and_then(|_| handle.sync_all()) {
        let _ = fs::remove_file(&staged_path);
        return Err(error);
    }
    drop(handle);

    let staged_hash = sha256_file(&staged_path)?;
    if !validate_hash(expected_hash, &staged_hash) {
        let _ = fs::remove_file(&staged_path);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged update failed integrity verification",
        ));
    }

    Ok(staged_path)
}

fn tempfile_path() -> PathBuf {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "ztsec-agent-update-{}-{timestamp:x}.exe",
        std::process::id()
    ))
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    // Heap-backed buffer: the Windows executable's main thread has a finite stack.
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }

    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Debug)]
struct SuccessorArgs {
    source: PathBuf,
    target: PathBuf,
    hash: String,
    parent_pid: u32,
    server_ip: String,
    server_port: u16,
    fingerprint: String,
    handoff_port: u16,
    handoff_token: String,
    launch_args: Vec<OsString>,
}

fn parse_u16(value: &str, label: &str) -> Result<u16, String> {
    let parsed = value
        .parse::<u16>()
        .map_err(|_| format!("invalid {label}"))?;
    if parsed == 0 {
        return Err(format!("invalid {label}"));
    }
    Ok(parsed)
}

fn successor_args(args: &[String]) -> Result<Option<SuccessorArgs>, String> {
    let mut found = false;
    let mut source = None;
    let mut target = None;
    let mut hash = None;
    let mut parent_pid = None;
    let mut server_ip = None;
    let mut server_port = None;
    let mut fingerprint = None;
    let mut handoff_port = None;
    let mut handoff_token = None;
    let mut launch_args = Vec::new();

    for argument in args {
        if argument == SUCCESSOR_FLAG {
            found = true;
        } else if let Some(value) = argument.strip_prefix(SOURCE_ARG) {
            source = Some(PathBuf::from(value));
        } else if let Some(value) = argument.strip_prefix(TARGET_ARG) {
            target = Some(PathBuf::from(value));
        } else if let Some(value) = argument.strip_prefix(HASH_ARG) {
            hash = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix(PARENT_ARG) {
            parent_pid = Some(
                value
                    .parse::<u32>()
                    .map_err(|_| "invalid update parent pid".to_owned())?,
            );
        } else if let Some(value) = argument.strip_prefix(SERVER_IP_ARG) {
            server_ip = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix(SERVER_PORT_ARG) {
            server_port = Some(parse_u16(value, "update server port")?);
        } else if let Some(value) = argument.strip_prefix(FINGERPRINT_ARG) {
            fingerprint = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix(HANDOFF_PORT_ARG) {
            handoff_port = Some(parse_u16(value, "update handoff port")?);
        } else if let Some(value) = argument.strip_prefix(HANDOFF_TOKEN_ARG) {
            handoff_token = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix(LAUNCH_ARG) {
            launch_args.push(OsString::from(value));
        }
    }

    if !found {
        return Ok(None);
    }

    let hash = hash.ok_or("missing update hash")?;
    let fingerprint = fingerprint.ok_or("missing update fingerprint")?;
    let handoff_token = handoff_token.ok_or("missing update handoff token")?;

    if !validate_hash(&hash, &hash) {
        return Err("invalid update hash".into());
    }
    if !valid_fingerprint(&fingerprint) {
        return Err("invalid update fingerprint".into());
    }
    if handoff_token.len() != 64 || !handoff_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid update handoff token".into());
    }

    Ok(Some(SuccessorArgs {
        source: source.ok_or("missing update source")?,
        target: target.ok_or("missing update target")?,
        hash,
        parent_pid: parent_pid.ok_or("missing update parent pid")?,
        server_ip: server_ip.ok_or("missing update server ip")?,
        server_port: server_port.ok_or("missing update server port")?,
        fingerprint,
        handoff_port: handoff_port.ok_or("missing update handoff port")?,
        handoff_token,
        launch_args,
    }))
}

struct UpdateHandoff {
    listener: TcpListener,
    token: String,
    hash: String,
    fingerprint: String,
}

impl UpdateHandoff {
    fn new(hash: String, fingerprint: String) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            token: random_token()?,
            hash,
            fingerprint,
        })
    }

    fn port(&self) -> io::Result<u16> {
        match self.listener.local_addr()? {
            std::net::SocketAddr::V4(address) => Ok(address.port()),
            _ => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "IPv4 handoff listener required",
            )),
        }
    }

    pub(crate) fn wait_admission(self) -> io::Result<()> {
        let deadline = Instant::now() + PROBE_WAIT;

        while Instant::now() < deadline {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_read_timeout(Some(PROBE_READ_TIMEOUT))?;
                    let cloned = stream.try_clone()?;
                    let mut reader = BufReader::new(cloned);
                    let mut line = String::new();
                    if reader.read_line(&mut line)? == 0 {
                        continue;
                    }

                    let message = line.trim_end_matches(&['\r', '\n'][..]);
                    if let Some(rest) = message.strip_prefix(PROBE_READY_PREFIX) {
                        let parts: Vec<&str> = rest.split(':').collect();
                        if parts.len() == 3
                            && parts[0] == self.token
                            && validate_hash(&self.hash, parts[1])
                            && parts[2].eq_ignore_ascii_case(&self.fingerprint)
                        {
                            send_line(
                                &mut stream,
                                &format!("{PROBE_READY_ACK_PREFIX}{}", self.token),
                            )?;
                            return Ok(());
                        }
                    } else if let Some(rest) = message.strip_prefix(PROBE_FAILED_PREFIX) {
                        let parts: Vec<&str> = rest.splitn(2, ':').collect();
                        if parts.len() == 2 && parts[0] == self.token {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                parts[1].to_owned(),
                            ));
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "updated agent admission timed out",
        ))
    }
}

fn random_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
    Ok(bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(windows)]
fn wait_for_process_exit(pid: u32) -> io::Result<()> {
    type Handle = *mut core::ffi::c_void;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const WAIT_OBJECT_0: u32 = 0x0000_0000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> Handle;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        // Invalid PID means the process has already exited. Other failures must be surfaced.
        return if error.raw_os_error() == Some(87) {
            Ok(())
        } else {
            Err(error)
        };
    }

    let result = unsafe { WaitForSingleObject(handle, PARENT_WAIT.as_millis() as u32) };
    unsafe {
        CloseHandle(handle);
    }

    match result {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "update parent did not exit before timeout",
        )),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(not(windows))]
fn wait_for_process_exit(_pid: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn wide(value: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn replace_file(source: &Path, target: &Path) -> io::Result<()> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing_name: *const u16, new_name: *const u16, flags: u32) -> i32;
    }

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    let source_wide = wide(source.as_os_str());
    let target_wide = wide(target.as_os_str());
    let ok = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };

    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(source: &Path, target: &Path) -> io::Result<()> {
    fs::rename(source, target)
}

#[cfg(windows)]
fn launch_updated(target: &Path, arguments: &[OsString]) -> io::Result<()> {
    use std::os::windows::process::CommandExt;

    Command::new(target)
        .args(arguments)
        // Detached child; the helper can terminate immediately after starting the agent.
        .creation_flags(0x0800_0000)
        .spawn()
        .map(|_| ())
}

#[cfg(not(windows))]
fn launch_updated(target: &Path, arguments: &[OsString]) -> io::Result<()> {
    Command::new(target).args(arguments).spawn().map(|_| ())
}

fn rollback_path(target: &Path) -> PathBuf {
    target.with_extension("exe.ztsec-backup")
}

fn helper_path() -> PathBuf {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "ztsec-agent-update-helper-{}-{timestamp:x}.exe",
        std::process::id()
    ))
}

fn send_line(stream: &mut TcpStream, line: &str) -> io::Result<()> {
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn notify_handoff_failure(port: u16, token: &str, reason: &str) {
    let address = match format!("127.0.0.1:{port}").parse() {
        Ok(address) => address,
        Err(_) => return,
    };

    if let Ok(mut stream) = TcpStream::connect_timeout(&address, HANDOFF_CONNECT_TIMEOUT) {
        let sanitized = reason.replace(&['\r', '\n', ':'][..], " ");
        let _ = send_line(
            &mut stream,
            &format!("{PROBE_FAILED_PREFIX}{token}:{sanitized}"),
        );
    }
}

struct ProbeArgs {
    server_ip: String,
    server_port: u16,
    handoff_port: u16,
    handoff_token: String,
    expected_hash: String,
    expected_fingerprint: String,
}

fn probe_args(args: &[String]) -> Result<Option<ProbeArgs>, String> {
    let mut found = false;
    let mut server_ip = None;
    let mut server_port = None;
    let mut handoff_port = None;
    let mut handoff_token = None;
    let mut expected_hash = None;
    let mut expected_fingerprint = None;

    for argument in args {
        if argument == PROBE_FLAG {
            found = true;
        } else if let Some(value) = argument.strip_prefix(SERVER_IP_ARG) {
            server_ip = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix(SERVER_PORT_ARG) {
            server_port = Some(parse_u16(value, "probe server port")?);
        } else if let Some(value) = argument.strip_prefix(HANDOFF_PORT_ARG) {
            handoff_port = Some(parse_u16(value, "probe handoff port")?);
        } else if let Some(value) = argument.strip_prefix(HANDOFF_TOKEN_ARG) {
            handoff_token = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix(HASH_ARG) {
            expected_hash = Some(value.to_owned());
        } else if let Some(value) = argument.strip_prefix(FINGERPRINT_ARG) {
            expected_fingerprint = Some(value.to_owned());
        }
    }

    if !found {
        return Ok(None);
    }

    let handoff_token = handoff_token.ok_or("missing probe handoff token")?;
    let expected_hash = expected_hash.ok_or("missing probe update hash")?;
    let expected_fingerprint = expected_fingerprint.ok_or("missing probe fingerprint")?;

    if handoff_token.len() != 64
        || !handoff_token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid probe handoff token".into());
    }
    if !validate_hash(&expected_hash, &expected_hash) {
        return Err("invalid probe update hash".into());
    }
    if !valid_fingerprint(&expected_fingerprint) {
        return Err("invalid probe fingerprint".into());
    }

    Ok(Some(ProbeArgs {
        server_ip: server_ip.ok_or("missing probe server ip")?,
        server_port: server_port.ok_or("missing probe server port")?,
        handoff_port: handoff_port.ok_or("missing probe handoff port")?,
        handoff_token,
        expected_hash,
        expected_fingerprint,
    }))
}

fn probe_entry(args: &[String]) -> Result<(), String> {
    let probe = probe_args(args)?.ok_or("probe flag missing")?;
    let source = std::env::current_exe().map_err(|error| error.to_string())?;

    run_probe(
        &source,
        &probe.server_ip,
        probe.server_port,
        probe.handoff_port,
        &probe.handoff_token,
        &probe.expected_hash,
        &probe.expected_fingerprint,
    )
    .map_err(|error| error.to_string())
}

fn spawn_probe(successor: &SuccessorArgs) -> io::Result<Child> {
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    let mut command = Command::new(&successor.source);
    command
        .arg(PROBE_FLAG)
        .arg(format!("{SERVER_IP_ARG}{}", successor.server_ip))
        .arg(format!("{SERVER_PORT_ARG}{}", successor.server_port))
        .arg(format!("{HANDOFF_PORT_ARG}{}", successor.handoff_port))
        .arg(format!("{HANDOFF_TOKEN_ARG}{}", successor.handoff_token))
        .arg(format!("{HASH_ARG}{}", successor.hash))
        .arg(format!("{FINGERPRINT_ARG}{}", successor.fingerprint));

    #[cfg(windows)]
    command.creation_flags(0x0800_0000);

    command.spawn()
}

fn cleanup_update_artifacts(source: &Path, target_tmp: &Path, backup: &Path) {
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(target_tmp);
    let _ = fs::remove_file(backup);
}

fn restart_original_after_failure(
    target: &Path,
    arguments: &[OsString],
    source: &Path,
    target_tmp: &Path,
    backup: &Path,
    original_error: io::Error,
) -> io::Result<()> {
    let mut restore_error = None;
    if !target.exists() && backup.exists() {
        for attempt in 0..REPLACEMENT_RETRIES {
            match replace_file(backup, target) {
                Ok(()) => {
                    restore_error = None;
                    break;
                }
                Err(error) => {
                    restore_error = Some(error);
                    if attempt + 1 < REPLACEMENT_RETRIES {
                        std::thread::sleep(REPLACEMENT_RETRY_DELAY);
                    }
                }
            }
        }
    }

    let restart_error = launch_updated(target, arguments).err();

    let _ = fs::remove_file(source);
    let _ = fs::remove_file(target_tmp);
    if backup.exists() && target.exists() {
        let _ = fs::remove_file(backup);
    }

    match (restore_error, restart_error) {
        (Some(restore), Some(restart)) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "update failed: {original_error}; original target restore failed: {restore}; original-agent restart failed: {restart}"
            ),
        )),
        (Some(restore), None) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("update failed: {original_error}; original target restore failed: {restore}"),
        )),
        (None, Some(restart)) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("update failed: {original_error}; original-agent restart failed: {restart}"),
        )),
        (None, None) => Err(original_error),
    }
}

fn replace_and_launch(successor: &SuccessorArgs) -> io::Result<()> {
    let parent = match successor.target.parent() {
        Some(parent) => parent,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "update target has no parent",
            ));
        }
    };

    let target_tmp = parent.join(format!(
        ".ztsec-update-{}.new.exe",
        std::process::id()
    ));
    let backup = rollback_path(&successor.target);

    // The original process has already exited when this helper reaches this function.
    // Therefore every failure below must either restore/restart the original agent or
    // leave the target untouched and start it again. Never strand the machine without
    // an agent just because replacement preparation failed.
    let staged_hash = match sha256_file(&successor.source) {
        Ok(hash) => hash,
        Err(error) => {
            return restart_original_after_failure(
                &successor.target,
                &successor.launch_args,
                &successor.source,
                &target_tmp,
                &backup,
                io::Error::new(
                    error.kind(),
                    format!("successor source verification failed: {error}"),
                ),
            );
        }
    };
    if !validate_hash(&successor.hash, &staged_hash) {
        return restart_original_after_failure(
            &successor.target,
            &successor.launch_args,
            &successor.source,
            &target_tmp,
            &backup,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "successor source failed integrity verification",
            ),
        );
    }

    if let Err(error) = fs::create_dir_all(parent) {
        return restart_original_after_failure(
            &successor.target,
            &successor.launch_args,
            &successor.source,
            &target_tmp,
            &backup,
            error,
        );
    }

    let _ = fs::remove_file(&target_tmp);
    if backup.exists() {
        let _ = fs::remove_file(&backup);
    }

    if let Err(error) = fs::copy(&successor.source, &target_tmp) {
        return restart_original_after_failure(
            &successor.target,
            &successor.launch_args,
            &successor.source,
            &target_tmp,
            &backup,
            error,
        );
    }

    let target_tmp_hash = match sha256_file(&target_tmp) {
        Ok(hash) => hash,
        Err(error) => {
            return restart_original_after_failure(
                &successor.target,
                &successor.launch_args,
                &successor.source,
                &target_tmp,
                &backup,
                error,
            );
        }
    };
    if !validate_hash(&successor.hash, &target_tmp_hash) {
        return restart_original_after_failure(
            &successor.target,
            &successor.launch_args,
            &successor.source,
            &target_tmp,
            &backup,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "replacement copy failed integrity verification",
            ),
        );
    }

    if successor.target.exists() {
        if let Err(error) = fs::copy(&successor.target, &backup) {
            return restart_original_after_failure(
                &successor.target,
                &successor.launch_args,
                &successor.source,
                &target_tmp,
                &backup,
                error,
            );
        }
    }

    let mut replacement_error = None;
    for attempt in 0..REPLACEMENT_RETRIES {
        match replace_file(&target_tmp, &successor.target) {
            Ok(()) => {
                replacement_error = None;
                break;
            }
            Err(error) => {
                replacement_error = Some(error);
                if attempt + 1 < REPLACEMENT_RETRIES {
                    std::thread::sleep(REPLACEMENT_RETRY_DELAY);
                }
            }
        }
    }

    if let Some(error) = replacement_error {
        return restart_original_after_failure(
            &successor.target,
            &successor.launch_args,
            &successor.source,
            &target_tmp,
            &backup,
            error,
        );
    }

    match launch_updated(&successor.target, &successor.launch_args) {
        Ok(()) => {
            let _ = fs::remove_file(&backup);
            let _ = fs::remove_file(&successor.source);
            Ok(())
        }
        Err(launch_error) => {
            // The replacement succeeded, but the updated agent failed to launch.
            // Restore the original binary and make a best-effort restart so an update
            // failure never strands the machine without an agent process.
            let mut restored = false;
            if backup.exists() {
                for attempt in 0..REPLACEMENT_RETRIES {
                    if replace_file(&backup, &successor.target).is_ok() {
                        restored = true;
                        break;
                    }
                    if attempt + 1 < REPLACEMENT_RETRIES {
                        std::thread::sleep(REPLACEMENT_RETRY_DELAY);
                    }
                }
            }

            let restart_error = if restored {
                launch_updated(&successor.target, &successor.launch_args).err()
            } else {
                None
            };

            let _ = fs::remove_file(&successor.source);
            if let Some(error) = restart_error {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "updated agent launch failed: {launch_error}; original-agent restart failed: {error}"
                    ),
                ))
            } else if !restored && backup.exists() {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "updated agent launch failed: {launch_error}; original-agent restore failed"
                    ),
                ))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("updated agent launch failed: {launch_error}"),
                ))
            }
        }
    }
}

fn run_successor(successor: SuccessorArgs) -> io::Result<()> {
    let mut probe_child = match spawn_probe(&successor) {
        Ok(child) => child,
        Err(error) => {
            notify_handoff_failure(
                successor.handoff_port,
                &successor.handoff_token,
                &format!("could not start candidate: {error}"),
            );
            let _ = fs::remove_file(&successor.source);
            return Err(error);
        }
    };

    let probe_deadline = Instant::now() + CHILD_WAIT;
    loop {
        match probe_child.try_wait()? {
            Some(status) if status.success() => break,
            Some(status) => {
                let error = io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("updated agent probe failed: {status}"),
                );
                notify_handoff_failure(
                    successor.handoff_port,
                    &successor.handoff_token,
                    &error.to_string(),
                );
                let _ = fs::remove_file(&successor.source);
                return Err(error);
            }
            None if Instant::now() >= probe_deadline => {
                let _ = probe_child.kill();
                let _ = probe_child.wait();
                notify_handoff_failure(
                    successor.handoff_port,
                    &successor.handoff_token,
                    "updated agent probe timed out",
                );
                let _ = fs::remove_file(&successor.source);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "updated agent probe timed out",
                ));
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }

    match sha256_file(&successor.source) {
        Ok(staged_hash) if validate_hash(&successor.hash, &staged_hash) => {}
        Ok(_) => {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                "staged update changed before parent shutdown",
            );
            notify_handoff_failure(
                successor.handoff_port,
                &successor.handoff_token,
                &error.to_string(),
            );
            let _ = fs::remove_file(&successor.source);
            return Err(error);
        }
        Err(error) => {
            notify_handoff_failure(
                successor.handoff_port,
                &successor.handoff_token,
                &format!("could not verify staged update before parent shutdown: {error}"),
            );
            let _ = fs::remove_file(&successor.source);
            return Err(error);
        }
    }

    if let Err(error) = wait_for_process_exit(successor.parent_pid) {
        let _ = fs::remove_file(&successor.source);
        return Err(error);
    }

    replace_and_launch(&successor)
}

pub(crate) fn spawn_successor(
    staged: PathBuf,
    target: PathBuf,
    hash: String,
    parent_pid: u32,
    server_ip: &str,
    server_port: u16,
    fingerprint: &str,
) -> io::Result<UpdateHandoff> {
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    let helper = helper_path();
    if let Err(error) = fs::copy(std::env::current_exe()?, &helper) {
        let _ = fs::remove_file(&helper);
        return Err(error);
    }

    let handoff = match UpdateHandoff::new(hash.clone(), fingerprint.to_owned()) {
        Ok(handoff) => handoff,
        Err(error) => {
            let _ = fs::remove_file(&helper);
            return Err(error);
        }
    };
    let handoff_port = match handoff.port() {
        Ok(port) => port,
        Err(error) => {
            let _ = fs::remove_file(&helper);
            return Err(error);
        }
    };

    let mut command = Command::new(&helper);
    command
        .arg(SUCCESSOR_FLAG)
        .arg(format!("{SOURCE_ARG}{}", staged.display()))
        .arg(format!("{TARGET_ARG}{}", target.display()))
        .arg(format!("{HASH_ARG}{hash}"))
        .arg(format!("{PARENT_ARG}{parent_pid}"))
        .arg(format!("{SERVER_IP_ARG}{server_ip}"))
        .arg(format!("{SERVER_PORT_ARG}{server_port}"))
        .arg(format!("{FINGERPRINT_ARG}{fingerprint}"))
        .arg(format!("{HANDOFF_PORT_ARG}{handoff_port}"))
        .arg(format!("{HANDOFF_TOKEN_ARG}{}", handoff.token));

    for argument in std::env::args_os().skip(1) {
        let mut forwarded = OsString::from(LAUNCH_ARG);
        forwarded.push(argument);
        command.arg(forwarded);
    }

    #[cfg(windows)]
    command.creation_flags(0x0800_0000);

    if let Err(error) = command.spawn() {
        let _ = fs::remove_file(&helper);
        let _ = fs::remove_file(&staged);
        return Err(error);
    }

    Ok(handoff)
}

pub(crate) fn maybe_run_probe(args: &[String]) -> bool {
    if args.iter().any(|argument| argument == PROBE_FLAG) {
        match probe_entry(args) {
            Ok(()) => std::process::exit(0),
            Err(error) => {
                eprintln!("ztsec update probe failed: {error}");
                std::process::exit(1);
            }
        }
    }
    false
}

pub(crate) fn maybe_run_successor(args: &[String]) -> bool {
    match successor_args(args) {
        Ok(None) => false,
        Ok(Some(successor)) => {
            if let Err(error) = run_successor(successor) {
                eprintln!("ztsec update successor failed: {error}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("ztsec update successor arguments invalid: {error}");
            std::process::exit(2);
        }
    }
}

fn run_probe(
    source: &Path,
    server_ip: &str,
    server_port: u16,
    handoff_port: u16,
    handoff_token: &str,
    expected_hash: &str,
    expected_fingerprint: &str,
) -> io::Result<()> {
    let actual_hash = sha256_file(source)?;
    if !validate_hash(expected_hash, &actual_hash) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "probe executable hash mismatch",
        ));
    }

    let actual_fingerprint = telemetry::fingerprint();
    if !actual_fingerprint.eq_ignore_ascii_case(expected_fingerprint) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "probe fingerprint mismatch",
        ));
    }

    let mut addresses = (server_ip, server_port).to_socket_addrs()?;
    let mut last_error = None;
    let mut server_stream = None;

    while let Some(address) = addresses.next() {
        match TcpStream::connect_timeout(&address, PROBE_CONNECT_TIMEOUT) {
            Ok(stream) => {
                server_stream = Some(stream);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }

    let mut server_stream = server_stream.ok_or_else(|| {
        last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "update server resolved to no addresses",
            )
        })
    })?;
    server_stream.set_read_timeout(Some(PROBE_READ_TIMEOUT))?;

    send_line(
        &mut server_stream,
        &format!(
            "{PROBE_HELLO_PREFIX}{actual_fingerprint}:{handoff_token}:{actual_hash}"
        ),
    )?;

    // The panel deliberately requires a complete DATA frame before it admits the candidate.
    let telemetry_data = telemetry::record(server_ip, None, &actual_fingerprint);
    send_line(
        &mut server_stream,
        &format!("{}{}", crate::text::DATA, telemetry_data),
    )?;

    let cloned = server_stream.try_clone()?;
    let mut reader = BufReader::new(cloned);
    let expected_ack = format!(
        "{PROBE_ACK_PREFIX}{actual_fingerprint}:{handoff_token}"
    );
    let deadline = Instant::now() + PROBE_READ_TIMEOUT;

    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "update probe acknowledgement timed out",
            ));
        }

        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "server closed probe connection before acknowledgement",
            ));
        }

        let line = line.trim_end_matches(&['\r', '\n'][..]);
        if line == expected_ack {
            break;
        }
        if line.starts_with(crate::text::ERR) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                line.to_owned(),
            ));
        }
    }

    let address = format!("127.0.0.1:{handoff_port}")
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid handoff address"))?;
    let mut handoff = TcpStream::connect_timeout(&address, HANDOFF_CONNECT_TIMEOUT)?;
    handoff.set_read_timeout(Some(HANDOFF_READ_TIMEOUT))?;
    send_line(
        &mut handoff,
        &format!("{PROBE_READY_PREFIX}{handoff_token}:{actual_hash}:{actual_fingerprint}"),
    )?;

    let cloned = handoff.try_clone()?;
    let mut response_reader = BufReader::new(cloned);
    let mut response = String::new();
    response_reader.read_line(&mut response)?;
    if response.trim_end_matches(&['\r', '\n'][..])
        != format!("{PROBE_READY_ACK_PREFIX}{handoff_token}")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "old agent did not acknowledge probe readiness",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_and_hash_validation() {
        let value = sha256_hex(b"ztsec-update");
        assert_eq!(value.len(), 64);
        assert!(validate_hash(&value, &value.to_uppercase()));
        assert!(!validate_hash(&"0".repeat(64), &value));
        assert!(!validate_hash("no", &value));
    }

    #[test]
    fn base64_strict_decode() {
        assert_eq!(decode_base64("Wg=="), Some(vec![b'Z']));
        assert_eq!(decode_base64("Wg"), Some(vec![b'Z']));
        assert_eq!(decode_base64("Wg="), None);
        assert_eq!(decode_base64("Zh=="), None);
    }

    #[test]
    fn heap_hash_buffer() {
        let source = include_str!("update.rs");
        assert!(source.contains("let mut buffer = vec![0u8; 64 * 1024]"));
        assert!(!source.contains("let mut buf = [0u8; 1024 * 1024]"));
    }
}
