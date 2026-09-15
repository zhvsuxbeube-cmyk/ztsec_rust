use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

const MAX_UPDATE_BYTES: usize = 64 * 1024 * 1024;
const SUCCESSOR_FLAG: &str = "--ztsec-update-successor";
const SOURCE_ARG: &str = "--ztsec-update-source=";
const TARGET_ARG: &str = "--ztsec-update-target=";
const HASH_ARG: &str = "--ztsec-update-hash=";
const PARENT_ARG: &str = "--ztsec-update-parent=";
const LAUNCH_ARG: &str = "--ztsec-update-agent-arg=";
const WAIT_TIMEOUT_MS: u32 = 120_000;

pub(crate) fn max_update_bytes() -> usize {
    MAX_UPDATE_BYTES
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(crate) fn validate_hash(expected: &str, actual: &str) -> bool {
    let expected = expected.trim();
    expected.len() == 64
        && expected.bytes().all(|b| b.is_ascii_hexdigit())
        && expected.eq_ignore_ascii_case(actual)
}

pub(crate) fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let compact = s
        .bytes()
        .filter(|b| !matches!(b, b'\r' | b'\n' | b'\t' | b' '))
        .collect::<Vec<_>>();

    if compact.is_empty() || compact.len() > MAX_UPDATE_BYTES.saturating_mul(4) / 3 + 4 {
        return None;
    }

    fn value(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let rem = compact.len() & 3;
    if rem == 1 {
        return None;
    }

    let padded = compact.len() % 4 == 0;
    let mut out = Vec::with_capacity(compact.len() * 3 / 4);
    let mut i = 0usize;

    while i < compact.len() {
        let remaining = compact.len() - i;
        if remaining >= 4 {
            let a = value(compact[i])? as u32;
            let b = value(compact[i + 1])? as u32;
            let c = if compact[i + 2] == b'=' { 0 } else { value(compact[i + 2])? as u32 };
            let d = if compact[i + 3] == b'=' { 0 } else { value(compact[i + 3])? as u32 };
            let pad2 = compact[i + 2] == b'=';
            let pad1 = compact[i + 3] == b'=';

            if pad2 && !pad1 {
                return None;
            }
            if (pad2 || pad1) && i + 4 != compact.len() {
                return None;
            }

            out.push(((a << 2) | (b >> 4)) as u8);
            if !pad2 {
                out.push(((b << 4) | (c >> 2)) as u8);
            }
            if !pad1 {
                out.push(((c << 6) | d) as u8);
            }
            i += 4;
            continue;
        }

        if padded {
            return None;
        }

        let a = value(compact[i])? as u32;
        let b = value(compact[i + 1])? as u32;
        out.push(((a << 2) | (b >> 4)) as u8);
        if remaining == 3 {
            let c = value(compact[i + 2])? as u32;
            out.push(((b << 4) | (c >> 2)) as u8);
        }
        i = compact.len();
    }

    if out.is_empty() || out.len() > MAX_UPDATE_BYTES {
        return None;
    }
    Some(out)
}

pub(crate) fn stage_bytes(bytes: &[u8], expected_hash: &str) -> io::Result<PathBuf> {
    if bytes.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "update payload is empty"));
    }
    if bytes.len() > MAX_UPDATE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "update payload is too large"));
    }

    let actual = sha256_hex(bytes);
    if !validate_hash(expected_hash, &actual) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("hash mismatch: expected {}, got {}", expected_hash.trim(), actual),
        ));
    }

    let file = tempfile_path();
    let mut handle = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&file)?;

    if let Err(err) = handle.write_all(bytes).and_then(|_| handle.sync_all()) {
        let _ = fs::remove_file(&file);
        return Err(err);
    }
    drop(handle);

    // Re-open and verify the exact staged bytes before handing the file to the
    // successor. This catches partial writes and makes the handoff explicit.
    let staged_hash = sha256_file(&file)?;
    if !validate_hash(expected_hash, &staged_hash) {
        let _ = fs::remove_file(&file);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged update failed final integrity verification",
        ));
    }

    if let Err(err) = fs::metadata(&file) {
        let _ = fs::remove_file(&file);
        return Err(err);
    }

    Ok(file)
}

fn tempfile_path() -> PathBuf {
    let pid = std::process::id();
    let stamp = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    std::env::temp_dir().join(format!("ztsec-agent-update-{pid}-{stamp}.exe"))
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[derive(Debug, PartialEq, Eq)]
struct SuccessorArgs {
    source: PathBuf,
    target: PathBuf,
    hash: String,
    parent_pid: u32,
    launch_args: Vec<std::ffi::OsString>,
}

fn successor_args(args: &[String]) -> Result<Option<SuccessorArgs>, String> {
    let mut found = false;
    let mut source = None;
    let mut target = None;
    let mut hash = None;
    let mut parent_pid = None;
    let mut launch_args = Vec::new();

    for arg in args {
        if arg == SUCCESSOR_FLAG {
            found = true;
        } else if let Some(v) = arg.strip_prefix(SOURCE_ARG) {
            source = Some(PathBuf::from(v));
        } else if let Some(v) = arg.strip_prefix(TARGET_ARG) {
            target = Some(PathBuf::from(v));
        } else if let Some(v) = arg.strip_prefix(HASH_ARG) {
            hash = Some(v.to_owned());
        } else if let Some(v) = arg.strip_prefix(LAUNCH_ARG) {
            launch_args.push(std::ffi::OsString::from(v));
        } else if let Some(v) = arg.strip_prefix(PARENT_ARG) {
            parent_pid = Some(
                v.parse::<u32>()
                    .map_err(|_| "invalid update parent pid".to_owned())?,
            );
        }
    }

    if !found {
        return Ok(None);
    }

    let source = source.ok_or_else(|| "missing update source".to_owned())?;
    let target = target.ok_or_else(|| "missing update target".to_owned())?;
    let hash = hash.ok_or_else(|| "missing update hash".to_owned())?;
    let parent_pid = parent_pid.ok_or_else(|| "missing update parent pid".to_owned())?;

    if source.as_os_str().is_empty() || target.as_os_str().is_empty() || parent_pid == 0 {
        return Err("invalid update successor arguments".to_owned());
    }
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid update hash".to_owned());
    }

    Ok(Some(SuccessorArgs {
        source,
        target,
        hash,
        parent_pid,
        launch_args,
    }))
}

#[cfg(windows)]
fn wait_for_process_exit(pid: u32) -> io::Result<()> {
    type Handle = *mut core::ffi::c_void;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const WAIT_OBJECT_0: u32 = 0x0000_0000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    const WAIT_FAILED: u32 = 0xFFFF_FFFF;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        let err = io::Error::last_os_error();
        // ERROR_INVALID_PARAMETER means the PID no longer identifies a live
        // process. Other failures must not be treated as a safe handoff.
        if err.raw_os_error() == Some(87) {
            return Ok(());
        }
        return Err(err);
    }

    let result = unsafe { WaitForSingleObject(handle, WAIT_TIMEOUT_MS) };
    let _ = unsafe { CloseHandle(handle) };

    match result {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "update parent did not exit before timeout",
        )),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(io::Error::new(
            io::ErrorKind::Other,
            "unexpected wait result",
        )),
    }
}

#[cfg(not(windows))]
fn wait_for_process_exit(_pid: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn replace_file(source: &Path, target: &Path) -> io::Result<()> {
    type Bool = i32;
    type Dword = u32;
    const MOVEFILE_REPLACE_EXISTING: Dword = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: Dword = 0x0000_0008;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: Dword) -> Bool;
    }

    let source_w = wide(source.as_os_str());
    let target_w = wide(target.as_os_str());
    let ok = unsafe {
        MoveFileExW(
            source_w.as_ptr(),
            target_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(source: &Path, target: &Path) -> io::Result<()> {
    fs::rename(source, target)
}

#[cfg(windows)]
fn launch_updated(target: &Path, launch_args: &[std::ffi::OsString]) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new(target)
        .args(launch_args)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map(|_| ())
}

#[cfg(not(windows))]
fn launch_updated(target: &Path, launch_args: &[std::ffi::OsString]) -> io::Result<()> {
    std::process::Command::new(target).spawn().map(|_| ())
}

fn rollback_path(target: &Path) -> PathBuf {
    target.with_extension("exe.ztsec-backup")
}

fn helper_path() -> PathBuf {
    let pid = std::process::id();
    let stamp = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    std::env::temp_dir().join(format!("ztsec-agent-update-helper-{pid}-{stamp}.exe"))
}

fn run_successor(successor: SuccessorArgs) -> io::Result<()> {
    wait_for_process_exit(successor.parent_pid)?;

    let staged_hash = sha256_file(&successor.source)?;
    if !validate_hash(&successor.hash, &staged_hash) {
        let _ = fs::remove_file(&successor.source);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "successor source failed integrity verification",
        ));
    }

    let parent = successor
        .target
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "update target has no parent"))?;
    fs::create_dir_all(parent)?;

    let target_tmp = parent.join(format!(
        ".ztsec-update-{}.new.exe",
        std::process::id()
    ));
    fs::copy(&successor.source, &target_tmp)?;
    let copied_hash = sha256_file(&target_tmp)?;
    if !validate_hash(&successor.hash, &copied_hash) {
        let _ = fs::remove_file(&target_tmp);
        let _ = fs::remove_file(&successor.source);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "replacement copy failed integrity verification",
        ));
    }

    let backup = rollback_path(&successor.target);
    let _ = fs::remove_file(&backup);

    if successor.target.exists() {
        fs::copy(&successor.target, &backup)?;
    }

    let mut replacement_error = None;
    for attempt in 0..40 {
        match replace_file(&target_tmp, &successor.target) {
            Ok(()) => {
                replacement_error = None;
                break;
            }
            Err(err) => {
                replacement_error = Some(err);
                if attempt < 39 {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            }
        }
    }
    if let Some(err) = replacement_error {
        let _ = fs::remove_file(&target_tmp);
        let _ = fs::remove_file(&successor.source);
        return Err(err);
    }

    match launch_updated(&successor.target, &successor.launch_args) {
        Ok(()) => {
            let _ = fs::remove_file(&backup);
            let _ = fs::remove_file(&successor.source);
            Ok(())
        }
        Err(err) => {
            let _ = fs::remove_file(&successor.target);
            if backup.exists() {
                for attempt in 0..40 {
                    if replace_file(&backup, &successor.target).is_ok() {
                        break;
                    }
                    if attempt < 39 {
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }
                }
            }
            let _ = fs::remove_file(&successor.source);
            Err(err)
        }
    }
}

pub(crate) fn spawn_successor(
    staged: PathBuf,
    target: PathBuf,
    hash: String,
    parent_pid: u32,
) -> io::Result<()> {
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    #[cfg(windows)]
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // The successor must not execute from `target`: on Windows the running
    // executable is locked and cannot safely replace itself. Copy the current
    // executable to a temporary helper path, run that helper, and let it
    // promote the verified staged payload into the original target path.
    let current = std::env::current_exe()?;
    let helper = helper_path();
    fs::copy(&current, &helper)?;

    let mut cmd = std::process::Command::new(&helper);
    cmd.arg(SUCCESSOR_FLAG)
        .arg(format!("{SOURCE_ARG}{}", staged.display()))
        .arg(format!("{TARGET_ARG}{}", target.display()))
        .arg(format!("{HASH_ARG}{hash}"))
        .arg(format!("{PARENT_ARG}{parent_pid}"));

    let current_args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    for arg in current_args {
        cmd.arg(format!("{LAUNCH_ARG}{}", arg.to_string_lossy()));
    }

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    if let Err(err) = cmd.spawn() {
        let _ = fs::remove_file(&helper);
        return Err(err);
    }
    Ok(())
}

/// Handle `--ztsec-update-successor ...` before the normal single-instance
/// mutex is acquired. Returns true when the process was an update helper and
/// therefore should not continue into the agent runtime.
pub(crate) fn maybe_run_successor(args: &[String]) -> bool {
    match successor_args(args) {
        Ok(None) => false,
        Ok(Some(successor)) => {
            if let Err(err) = run_successor(successor) {
                eprintln!("ztsec update successor failed: {err}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Err(err) => {
            eprintln!("ztsec update successor arguments invalid: {err}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_and_hash_validation() {
        let actual = sha256_hex(b"ztsec-update");
        assert_eq!(actual.len(), 64);
        assert!(validate_hash(&actual, &actual.to_uppercase()));
        assert!(!validate_hash(&"0".repeat(64), &actual));
        assert!(!validate_hash("not-a-hash", &actual));
    }

    #[test]
    fn base64_strict_decode() {
        assert_eq!(decode_base64("Wg=="), Some(vec![b'Z']));
        assert_eq!(decode_base64("WkhzZWM="), Some(b"ZHsec".to_vec()));
        assert_eq!(decode_base64("Wg"), Some(vec![b'Z']));
        assert_eq!(decode_base64("WkE"), Some(b"ZA".to_vec()));
        assert_eq!(decode_base64("Wg="), None);
        assert_eq!(decode_base64("===="), None);
        assert_eq!(decode_base64("!A=="), None);
    }

    #[test]
    fn successor_argument_contract() {
        let args = vec![
            "ztsec_agent.exe".to_owned(),
            SUCCESSOR_FLAG.to_owned(),
            format!("{SOURCE_ARG}C:\\temp\\update.exe"),
            format!("{TARGET_ARG}C:\\app\\ztsec_agent.exe"),
            format!("{HASH_ARG}{}", "a".repeat(64)),
            format!("{PARENT_ARG}1234"),
        ];
        let got = successor_args(&args).unwrap().unwrap();
        assert_eq!(got.hash, "a".repeat(64));
        assert_eq!(got.parent_pid, 1234);
        assert!(got.launch_args.is_empty());
        assert_eq!(got.source, PathBuf::from(r"C:\temp\update.exe"));
        assert_eq!(got.target, PathBuf::from(r"C:\app\ztsec_agent.exe"));
    }

    #[test]
    fn successor_argument_absent() {
        let args = vec!["ztsec_agent.exe".to_owned()];
        assert_eq!(successor_args(&args).unwrap(), None);
    }

    #[test]
    fn successor_preserves_agent_arguments() {
        let args = vec![
            "ztsec_agent.exe".to_owned(),
            SUCCESSOR_FLAG.to_owned(),
            format!("{SOURCE_ARG}C:\\temp\\update.exe"),
            format!("{TARGET_ARG}C:\\app\\ztsec_agent.exe"),
            format!("{HASH_ARG}{}", "b".repeat(64)),
            format!("{PARENT_ARG}5678"),
            format!("{LAUNCH_ARG}--ip"),
            format!("{LAUNCH_ARG}10.0.0.7"),
            format!("{LAUNCH_ARG}--port"),
            format!("{LAUNCH_ARG}4796"),
        ];
        let got = successor_args(&args).unwrap().unwrap();
        assert_eq!(got.launch_args, vec![
            std::ffi::OsString::from("--ip"),
            std::ffi::OsString::from("10.0.0.7"),
            std::ffi::OsString::from("--port"),
            std::ffi::OsString::from("4796"),
        ]);
    }

    #[test]
    fn stage_bytes_rejects_wrong_hash_and_accepts_valid_bytes() {
        let bytes = b"not-really-an-exe";
        let err = stage_bytes(bytes, &"0".repeat(64)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let hash = sha256_hex(bytes);
        let path = stage_bytes(bytes, &hash).unwrap();
        assert!(path.is_file());
        assert_eq!(sha256_file(&path).unwrap(), hash);
        fs::remove_file(path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn replacement_keeps_target_path_and_installs_exact_bytes() {
        let root = std::env::temp_dir().join(format!(
            "ztsec-update-replace-test-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("candidate.exe");
        let target = root.join("ztsec_agent.exe");
        let bytes = b"MZ-zts-test-new-image";
        fs::write(&source, bytes).unwrap();
        fs::write(&target, b"MZ-zts-test-old-image").unwrap();

        replace_file(&source, &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert!(!source.exists());
        assert_eq!(target.file_name().unwrap(), "ztsec_agent.exe");

        let _ = fs::remove_dir_all(root);
    }
}
