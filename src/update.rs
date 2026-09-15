use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub const MAX_UPDATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_UPDATE_B64: usize = ((MAX_UPDATE_BYTES + 2) / 3) * 4 + 4;

static UPDATE_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

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

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name == Path::new(name).file_name().and_then(|v| v.to_str()).unwrap_or("")
        && !name.chars().any(|c| {
            c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        })
}

const UPDATE_SUFFIX: &str = "_update";

fn up_name(name: &str) -> Result<String, String> {
    if !safe_name(name) {
        return Err("invalid executable name".into());
    }
    let (stem, ext) = name.rsplit_once('.')
        .map(|(a, b)| (a, format!(".{b}")))
        .unwrap_or((name, String::new()));
    if stem.is_empty() || stem == "." || stem == ".." {
        return Err("invalid executable name".into());
    }
    Ok(format!("{stem}{UPDATE_SUFFIX}{ext}"))
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::{
        ffi::OsString,
        io::Write,
        os::windows::{ffi::OsStringExt, process::CommandExt},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    use crate::sys;

    const NO_WINDOW: u32 = 0x0800_0000;
    const UPDATE_TIMEOUT: Duration = Duration::from_secs(60);

    pub struct PreparedUpdate {
        path: PathBuf,
        dir: PathBuf,
    }

    pub fn prepare(bytes: &[u8]) -> Result<PreparedUpdate, String> {
        if UPDATE_IN_PROGRESS.swap(true, Ordering::AcqRel) {
            return Err("update already in progress".into());
        }

        let result = (|| {
            if bytes.is_empty() || bytes.len() > MAX_UPDATE_BYTES {
                return Err("invalid update size".into());
            }

            validate_pe(bytes)?;

            let old = current_executable()?;
            let dir = old.parent().ok_or("invalid executable path")?.to_path_buf();
            let file = old.file_name().ok_or("invalid executable name")?.to_string_lossy();
            let path = dir.join(up_name(&file)?);
            if path.parent() != Some(dir.as_path()) || path == old || path.exists() {
                return Err("update file already exists".into());
            }

            let _ = fs::remove_file(dir.join("success.txt"));
            let _ = fs::remove_file(dir.join("failed.txt"));
            write_file(&path, bytes)?;
            Ok(PreparedUpdate { path, dir })
        })();

        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                UPDATE_IN_PROGRESS.store(false, Ordering::Release);
                Err(e)
            }
        }
    }

    impl PreparedUpdate {
        pub fn finish(self) -> Result<(), String> {
            if !sys::release() {
                return Err("failed to release mutex".into());
            }

            let mut child = match Command::new(&self.path)
                .current_dir(&self.dir)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(NO_WINDOW)
                .spawn()
            {
                Ok(v) => v,
                Err(e) => {
                    let _ = fs::remove_file(&self.path);
                    let _ = sys::acquire(Duration::from_secs(5));
                    return Err(format!("failed to start update: {e}"));
                }
            };

            match wait_marker(&self.dir) {
                Marker::Success => {
                    let _ = fs::remove_file(self.dir.join("success.txt"));
                    UPDATE_IN_PROGRESS.store(false, Ordering::Release);
                    std::mem::forget(self);
                    Ok(())
                }
                Marker::Failed | Marker::Timeout => {
                    stop(&mut child);
                    let _ = fs::remove_file(self.dir.join("failed.txt"));
                    let _ = fs::remove_file(&self.path);
                    if !sys::acquire(Duration::from_secs(5)) {
                        UPDATE_IN_PROGRESS.store(false, Ordering::Release);
                        return Err("update failed and mutex could not be restored".into());
                    }
                    UPDATE_IN_PROGRESS.store(false, Ordering::Release);
                    Err("update failed".into())
                }
            }
        }
    }

    impl Drop for PreparedUpdate {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            UPDATE_IN_PROGRESS.store(false, Ordering::Release);
        }
    }

    pub fn is_update() -> bool {
        let Ok(path) = current_executable() else { return false; };
        let Some(stem) = path.file_stem().map(|v| v.to_string_lossy().into_owned()) else { return false; };
        stem.to_ascii_lowercase().ends_with(UPDATE_SUFFIX)
    }

    pub fn run(ip: &str, port: u16) -> Result<(), String> {
        let exe = current_executable()?;
        let dir = exe.parent().ok_or("invalid executable path")?.to_path_buf();
        let file = exe.file_name().ok_or("invalid executable name")?.to_string_lossy();
        let stem = exe.file_stem().ok_or("invalid executable name")?.to_string_lossy();
        if !stem.to_ascii_lowercase().ends_with(UPDATE_SUFFIX) || !safe_name(&file) {
            return Err("invalid update executable name".into());
        }

        let base_stem = &stem[..stem.len() - UPDATE_SUFFIX.len()];
        if base_stem.is_empty() || base_stem == "." || base_stem == ".." {
            return Err("invalid update executable name".into());
        }
        let ext = exe.extension().map(|v| format!(".{v}", v = v.to_string_lossy())).unwrap_or_default();
        let base = dir.join(format!("{base_stem}{ext}"));
        if base.parent() != Some(dir.as_path()) || !safe_name(base.file_name().and_then(|v| v.to_str()).unwrap_or_default()) {
            let _ = marker(&dir, "failed.txt");
            return Err("invalid update path".into());
        }
        if !sys::single() {
            let _ = marker(&dir, "failed.txt");
            return Err("mutex unavailable".into());
        }

        let mut stream = match std::net::TcpStream::connect((ip, port)) {
            Ok(v) => v,
            Err(_) => {
                let _ = marker(&dir, "failed.txt");
                return Err("panel connection failed".into());
            }
        };

        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        if stream.write_all(format!("{}\n", crate::text::UPDATE_HELLO).as_bytes()).is_err() {
            let _ = marker(&dir, "failed.txt");
            return Err("panel connection failed".into());
        }

        if !base.is_file() {
            let _ = marker(&dir, "failed.txt");
            return Err("original executable is missing".into());
        }

        if schedule_run(&dir, &base, &exe).is_err() {
            let _ = marker(&dir, "failed.txt");
            return Err("failed to schedule update".into());
        }
        marker(&dir, "success.txt")?;
        Ok(())
    }

    fn marker(dir: &Path, name: &str) -> Result<(), String> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(name))
            .map(|_| ())
            .map_err(|e| format!("failed to write update marker: {e}"))
    }

    fn wait_marker(dir: &Path) -> Marker {
        let deadline = Instant::now() + UPDATE_TIMEOUT;
        let ok = dir.join("success.txt");
        let bad = dir.join("failed.txt");
        loop {
            if ok.is_file() { return Marker::Success; }
            if bad.is_file() { return Marker::Failed; }
            if Instant::now() >= deadline { return Marker::Timeout; }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    enum Marker { Success, Failed, Timeout }

    fn schedule_run(dir: &Path, base: &Path, update: &Path) -> Result<(), String> {
        let base = base.file_name().and_then(|v| v.to_str()).ok_or("invalid base name")?.replace('%', "%%");
        let update = update.file_name().and_then(|v| v.to_str()).ok_or("invalid update name")?.replace('%', "%%");
        let cmd = format!(
            "ping 127.0.0.1 -n 3 >nul & move /Y \"{update}\" \"{base}\" >nul & start \"\" \"{base}\""
        );
        Command::new("cmd.exe")
            .args(["/D", "/C", &cmd])
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(NO_WINDOW)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("failed to schedule update: {e}"))
    }

    fn stop(child: &mut Child) {
        if child.try_wait().ok().flatten().is_none() { let _ = child.kill(); }
        let _ = child.wait();
    }

    fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(path)
            .map_err(|e| format!("failed to create update: {e}"))?;
        f.write_all(bytes).map_err(|e| format!("update write failed: {e}"))?;
        f.sync_all().map_err(|e| format!("update sync failed: {e}"))?;
        Ok(())
    }

    fn current_executable() -> Result<PathBuf, String> {
        let mut buf = vec![0u16; 260];
        loop {
            let len = unsafe { GetModuleFileNameW(core::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
            if len == 0 { return Err("failed to resolve executable path".into()); }
            if len < buf.len() - 1 {
                return Ok(PathBuf::from(OsString::from_wide(&buf[..len])));
            }
            if buf.len() >= 32768 { return Err("executable path is too long".into()); }
            buf.resize(buf.len() * 2, 0);
        }
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleFileNameW(module: *mut core::ffi::c_void, buffer: *mut u16, size: u32) -> u32;
    }
}

#[cfg(windows)]
pub use windows_impl::{is_update, prepare, PreparedUpdate, run};

#[cfg(not(windows))]
pub struct PreparedUpdate;

#[cfg(not(windows))]
impl PreparedUpdate {
    pub fn finish(self) -> Result<(), String> { Err("Update is supported only on Windows".into()) }
}

#[cfg(not(windows))]
pub fn is_update() -> bool { false }

#[cfg(not(windows))]
pub fn run(_: &str, _: u16) -> Result<(), String> { Err("Update is supported only on Windows".into()) }

#[cfg(not(windows))]
pub fn prepare(_: &[u8]) -> Result<PreparedUpdate, String> {
    Err("Update is supported only on Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(up_name("ztsec_agent.exe").unwrap(), "ztsec_agent_update.exe");
        assert!(safe_name("ztsec_agent.exe"));
        assert!(!safe_name("..\\escape.exe"));
        assert!(!safe_name("C:\\escape.exe"));
        assert!(!safe_name(""));
    }

    #[test]
    fn base64_update_is_bounded_and_binary_safe() {
        let decoded = decode_b64_update("AAECAP8=").unwrap();
        assert_eq!(decoded, vec![0, 1, 2, 0, 255]);
        assert!(decode_b64_update(&"A".repeat(MAX_UPDATE_B64 + 1)).is_none());
    }
}
