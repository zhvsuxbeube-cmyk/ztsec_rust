use std::{
    fs::{self, OpenOptions},
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub const MAX_UPDATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_UPDATE_B64: usize = ((MAX_UPDATE_BYTES + 2) / 3) * 4 + 4;

static UPDATE_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

pub fn normalize_filename(input: &str) -> Result<String, String> {
    let value = input.trim();
    if value.is_empty() {
        return Err("update filename is empty".into());
    }
    if value.len() > 240 {
        return Err("update filename is too long".into());
    }
    if value == "." || value == ".." || value.ends_with('.') || value.ends_with(' ') {
        return Err("invalid update filename".into());
    }
    if value.chars().any(|c| {
        c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
    }) {
        return Err("invalid update filename".into());
    }

    let filename = if value.to_ascii_lowercase().ends_with(".exe") {
        value.to_owned()
    } else {
        format!("{value}.exe")
    };

    let stem = filename
        .strip_suffix(".exe")
        .or_else(|| filename.strip_suffix(".EXE"))
        .unwrap_or(&filename);
    if is_reserved_device_name(stem) {
        return Err("invalid update filename".into());
    }
    Ok(filename)
}

fn is_reserved_device_name(value: &str) -> bool {
    let base = value.split('.').next().unwrap_or(value).to_ascii_uppercase();
    matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "COM2" | "COM3" | "COM4" | "COM5"
            | "COM6" | "COM7" | "COM8" | "COM9" | "LPT1" | "LPT2" | "LPT3" | "LPT4"
            | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
    )
}

pub fn decode_b64_update(input: &str) -> Option<Vec<u8>> {
    let s = input.trim();
    if s.is_empty() || s.len() > MAX_UPDATE_B64 {
        return None;
    }

    let mut out = Vec::with_capacity((s.len() / 4).saturating_mul(3).min(MAX_UPDATE_BYTES));
    let mut buf = 0u32;
    let mut bits = 0u32;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if out.len() == MAX_UPDATE_BYTES {
                return None;
            }
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

pub fn validate_pe(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 0x100 {
        return Err("update executable is too small".into());
    }
    if bytes.get(0..2) != Some(b"MZ") {
        return Err("update payload is not a PE executable".into());
    }

    let pe_offset = read_u32(bytes, 0x3c).ok_or("invalid PE header")? as usize;
    if pe_offset < 0x40 || pe_offset.checked_add(24).is_none() || pe_offset + 24 > bytes.len() {
        return Err("invalid PE header offset".into());
    }
    if bytes.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
        return Err("update payload has an invalid PE signature".into());
    }

    let machine = read_u16(bytes, pe_offset + 4).ok_or("invalid PE file header")?;
    let section_count = read_u16(bytes, pe_offset + 6).ok_or("invalid PE section count")? as usize;
    let optional_size = read_u16(bytes, pe_offset + 20).ok_or("invalid PE optional-header size")? as usize;
    let optional_offset = pe_offset + 24;
    if optional_size < 2 || optional_offset + optional_size > bytes.len() {
        return Err("invalid PE optional header".into());
    }

    let expected_machine = if cfg!(target_arch = "x86_64") {
        0x8664
    } else if cfg!(target_arch = "x86") {
        0x014c
    } else {
        0
    };
    if machine != expected_machine {
        return Err("update executable architecture does not match the agent".into());
    }

    let magic = read_u16(bytes, optional_offset).ok_or("invalid PE optional-header magic")?;
    let expected_magic = if cfg!(target_arch = "x86_64") { 0x20b } else { 0x10b };
    if magic != expected_magic {
        return Err("update executable format does not match the agent".into());
    }

    let size_of_image = read_u32(bytes, optional_offset + 56).ok_or("invalid PE image size")?;
    let size_of_headers = read_u32(bytes, optional_offset + 60).ok_or("invalid PE header size")?;
    if size_of_image == 0 || size_of_headers == 0 || size_of_headers as usize > bytes.len() {
        return Err("invalid PE image layout".into());
    }

    let sections_offset = optional_offset + optional_size;
    let section_bytes = section_count
        .checked_mul(40)
        .ok_or("invalid PE section table")?;
    if sections_offset + section_bytes > bytes.len() {
        return Err("invalid PE section table".into());
    }

    for i in 0..section_count {
        let off = sections_offset + i * 40;
        let raw_size = read_u32(bytes, off + 16).ok_or("invalid PE section")? as usize;
        let raw_offset = read_u32(bytes, off + 20).ok_or("invalid PE section")? as usize;
        if raw_size > 0 {
            let end = raw_offset
                .checked_add(raw_size)
                .ok_or("invalid PE section bounds")?;
            if raw_offset < size_of_headers as usize || end > bytes.len() {
                return Err("invalid PE section bounds".into());
            }
        }
    }

    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::{
        ffi::{OsStr, OsString},
        os::windows::{ffi::{OsStrExt, OsStringExt}, process::CommandExt},
        process::{Child, Command, Stdio},
        sync::mpsc,
        thread,
        time::Duration,
    };

    use crate::sys;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const UPDATE_CHILD_ARG: &str = "--update-child";
    const UPDATE_SUCCESS: &str = "SUCCESS";
    const UPDATE_CHILD_TIMEOUT: Duration = Duration::from_secs(60);

    pub struct PreparedUpdate {
        target_path: PathBuf,
        old_path: PathBuf,
        committed: bool,
    }

    pub fn prepare(_ip: &str, _port: u16, filename: &str, bytes: &[u8]) -> Result<PreparedUpdate, String> {
        if UPDATE_IN_PROGRESS.swap(true, Ordering::AcqRel) {
            return Err("another update is already in progress".into());
        }

        let mut created_target: Option<PathBuf> = None;
        let result = (|| {
            if bytes.is_empty() || bytes.len() > MAX_UPDATE_BYTES {
                return Err("update payload size is invalid".into());
            }
            validate_pe(bytes)?;

            let normalized = normalize_filename(filename)?;
            let current = current_executable()?;
            let directory = current
                .parent()
                .ok_or("current executable has no installation directory")?
                .to_path_buf();
            let target = directory.join(&normalized);

            if target.file_name() != Some(OsStr::new(&normalized)) {
                return Err("invalid update target filename".into());
            }
            if same_path(&current, &target) {
                return Err("update filename must differ from the running executable because Windows locks the active image".into());
            }
            if target.exists() {
                return Err("update target already exists".into());
            }

            write_final_executable(&target, bytes)?;
            created_target = Some(target.clone());
            Ok(PreparedUpdate {
                target_path: target,
                old_path: current,
                committed: false,
            })
        })();

        match result {
            Ok(v) => Ok(v),
            Err(err) => {
                if let Some(path) = created_target {
                    let _ = fs::remove_file(path);
                }
                UPDATE_IN_PROGRESS.store(false, Ordering::Release);
                Err(err)
            }
        }
    }

    impl PreparedUpdate {
        pub fn filename(&self) -> String {
            self.target_path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default()
        }

        pub fn finish_after_disconnect(mut self, ip: &str, port: u16) -> Result<(), String> {
            // Minimal handoff: release -> launch -> successor connects -> SUCCESS.
            // There is no token, second mutex, or parent/child control protocol.
            eprintln!("[update-handoff] releasing normal mutex");
            if !sys::release_single() {
                return Err("failed to release the normal mutex for update".into());
            }

            eprintln!("[update-handoff] launching successor {}", self.target_path.display());
            let port_arg = port.to_string();
            let spawn_result = Command::new(&self.target_path)
                .args(["--ip", ip, "--port", &port_arg, UPDATE_CHILD_ARG])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();

            let mut child = match spawn_result {
                Ok(child) => child,
                Err(err) => {
                    let _ = fs::remove_file(&self.target_path);
                    if !sys::acquire_successor_mutex(Duration::from_secs(5)) {
                        return Err(format!("update launch failed: {err}; original could not reacquire the normal mutex"));
                    }
                    return Err(format!("update launch failed: {err}"));
                }
            };

            let Some(stdout) = child.stdout.take() else {
                terminate_child(&mut child);
                let _ = fs::remove_file(&self.target_path);
                if !sys::acquire_successor_mutex(Duration::from_secs(5)) {
                    return Err("update successor stdout pipe unavailable and original could not reacquire the normal mutex".into());
                }
                return Err("update successor stdout pipe unavailable".into());
            };

            if wait_for_success(stdout, UPDATE_CHILD_TIMEOUT) {
                eprintln!("[update-handoff] successor connected successfully");
                if let Err(err) = schedule_old_image_delete(&self.old_path) {
                    eprintln!("[update-handoff] warning: {err}");
                }
                self.committed = true;
                UPDATE_IN_PROGRESS.store(false, Ordering::Release);
                return Ok(());
            }

            eprintln!("[update-handoff] successor did not report SUCCESS within 60 seconds");
            terminate_child(&mut child);
            let _ = fs::remove_file(&self.target_path);
            if !sys::acquire_successor_mutex(Duration::from_secs(5)) {
                return Err("successor failed and original could not reacquire the normal mutex".into());
            }
            UPDATE_IN_PROGRESS.store(false, Ordering::Release);
            Err("successor did not reconnect to the panel within 60 seconds".into())
        }
    }

    impl Drop for PreparedUpdate {
        fn drop(&mut self) {
            if !self.committed {
                let _ = fs::remove_file(&self.target_path);
            }
            UPDATE_IN_PROGRESS.store(false, Ordering::Release);
        }
    }

    pub fn is_update_child() -> bool {
        std::env::args().any(|arg| arg == UPDATE_CHILD_ARG)
    }

    pub fn signal_success() -> io::Result<()> {
        let mut stdout = io::stdout();
        stdout.write_all(UPDATE_SUCCESS.as_bytes())?;
        stdout.write_all(b"\n")?;
        stdout.flush()
    }

    fn wait_for_success(mut stdout: std::process::ChildStdout, timeout: Duration) -> bool {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buffer = String::new();
            let result = io::BufReader::new(&mut stdout).read_line(&mut buffer).is_ok()
                && buffer.trim() == UPDATE_SUCCESS;
            let _ = tx.send(result);
        });
        rx.recv_timeout(timeout).unwrap_or(false)
    }

    fn schedule_old_image_delete(path: &Path) -> Result<(), String> {
        let quoted = format!("\"{}\"", path.display());
        Command::new("cmd.exe")
            .args(["/D", "/C", &format!("ping 127.0.0.1 -n 2 >nul & del /f /q {quoted}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|err| format!("failed to schedule old executable deletion: {err}"))?;
        Ok(())
    }

    fn terminate_child(child: &mut Child) {
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
    }

    fn write_final_executable(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| format!("failed to create update executable: {e}"))?;
            file.write_all(bytes).map_err(|e| format!("update write failed: {e}"))?;
            file.flush().map_err(|e| format!("update flush failed: {e}"))?;
            file.sync_all().map_err(|e| format!("update sync failed: {e}"))?;
            file.seek(SeekFrom::Start(0)).map_err(|e| format!("update validation seek failed: {e}"))?;
            let mut read_back = Vec::with_capacity(bytes.len());
            file.read_to_end(&mut read_back).map_err(|e| format!("update validation read failed: {e}"))?;
            if read_back != bytes {
                return Err("update binary integrity check failed after write".into());
            }
            validate_pe(&read_back)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(path);
        }
        result
    }

    fn current_executable() -> Result<PathBuf, String> {
        let mut size = 260usize;
        loop {
            let mut buffer = vec![0u16; size];
            let len = unsafe {
                GetModuleFileNameW(
                    core::ptr::null_mut(),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                )
            } as usize;
            if len == 0 {
                return Err("failed to resolve current executable path".into());
            }
            if len < buffer.len() - 1 {
                let path = PathBuf::from(OsString::from_wide(&buffer[..len]));
                return if path.is_absolute() {
                    Ok(path)
                } else {
                    fs::canonicalize(&path).map_err(|e| format!("failed to resolve current executable path: {e}"))
                };
            }
            if size >= 32768 {
                return Err("current executable path is too long".into());
            }
            size *= 2;
        }
    }

    fn same_path(left: &Path, right: &Path) -> bool {
        left.to_string_lossy().eq_ignore_ascii_case(&right.to_string_lossy())
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleFileNameW(module: *mut core::ffi::c_void, buffer: *mut u16, size: u32) -> u32;
    }
}

#[cfg(windows)]
pub use windows_impl::{is_update_child, prepare, signal_success, PreparedUpdate};

#[cfg(not(windows))]
pub struct PreparedUpdate;

#[cfg(not(windows))]
impl PreparedUpdate {
    pub fn filename(&self) -> String { String::new() }
    pub fn finish_after_disconnect(self, _ip: &str, _port: u16) -> Result<(), String> {
        Err("Update is supported only on Windows".into())
    }
}

#[cfg(not(windows))]
pub fn is_update_child() -> bool { false }

#[cfg(not(windows))]
pub fn signal_success() -> io::Result<()> { Ok(()) }

#[cfg(not(windows))]
pub fn prepare(_: &str, _: u16, _: &str, _: &[u8]) -> Result<PreparedUpdate, String> {
    Err("Update is supported only on Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_normalization() {
        assert_eq!(normalize_filename("agent").unwrap(), "agent.exe");
        assert_eq!(normalize_filename("agent.exe").unwrap(), "agent.exe");
        assert_eq!(normalize_filename("agent.EXE").unwrap(), "agent.EXE");
        assert!(normalize_filename("..\\escape.exe").is_err());
        assert!(normalize_filename("CON.exe").is_err());
    }

    #[test]
    fn base64_update_is_bounded_and_binary_safe() {
        let decoded = decode_b64_update("AAECAP8=").unwrap();
        assert_eq!(decoded, vec![0, 1, 2, 0, 255]);
        assert!(decode_b64_update(&"A".repeat(MAX_UPDATE_B64 + 1)).is_none());
    }
}
