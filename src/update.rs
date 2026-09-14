use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub const MAX_UPDATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_UPDATE_B64: usize = ((MAX_UPDATE_BYTES + 2) / 3) * 4 + 4;
const MAX_HANDOFF_IP_BYTES: usize = 512;
const MAX_HANDOFF_OLD_NAME_UTF16: usize = 255;
const HANDOFF_MAGIC: &[u8; 8] = b"ZTSUPD01";
const HANDOFF_TOKEN_BYTES: usize = 16;
const HANDOFF_INIT: &str = "INIT";
const HANDOFF_RELEASE: &str = "RELEASE";
const HANDOFF_READY: &str = "READY";
const HANDOFF_FAIL: &str = "FAIL";
const HANDOFF_INIT_TIMEOUT_MS: u64 = 10_000;
const HANDOFF_RELEASE_TIMEOUT_MS: u64 = 120_000;
const HANDOFF_READY_TIMEOUT_MS: u64 = 120_000;

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
    if value
        .chars()
        .any(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
    {
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
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
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
        os::windows::{ffi::{OsStrExt, OsStringExt}, io::{AsRawHandle, FromRawHandle, RawHandle}, process::CommandExt},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use crate::sys;

    type Handle = *mut core::ffi::c_void;
    type Bool = i32;

    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
    const FILE_TYPE_PIPE: u32 = 0x0003;
    const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;
    const WAIT_OBJECT_0: u32 = 0x0000_0000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    const INFINITE: u32 = 0xFFFF_FFFF;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut core::ffi::c_void,
        inherit_handle: Bool,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreatePipe(read: *mut Handle, write: *mut Handle, attrs: *mut SecurityAttributes, size: u32) -> Bool;
        fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> Bool;
        fn GetStdHandle(which: u32) -> Handle;
        fn GetFileType(handle: Handle) -> u32;
        fn PeekNamedPipe(handle: Handle, buffer: *mut u8, size: u32, read: *mut u32, available: *mut u32, left: *mut u32) -> Bool;
        fn OpenProcess(access: u32, inherit: Bool, process_id: u32) -> Handle;
        fn QueryFullProcessImageNameW(handle: Handle, flags: u32, buffer: *mut u16, size: *mut u32) -> Bool;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn CloseHandle(handle: Handle) -> Bool;
        fn DeleteFileW(path: *const u16) -> Bool;
        fn GetCurrentProcessId() -> u32;
        fn GetModuleFileNameW(module: Handle, buffer: *mut u16, size: u32) -> u32;
        fn Sleep(milliseconds: u32);
    }

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(algorithm: Handle, buffer: *mut u8, length: u32, flags: u32) -> i32;
    }

    pub struct PreparedUpdate {
        target_path: PathBuf,
        old_name: Vec<u16>,
        token: [u8; HANDOFF_TOKEN_BYTES],
        to_child: Option<std::fs::File>,
        child_stdin: Option<std::fs::File>,
        from_child: Option<std::fs::File>,
        child_stderr: Option<std::fs::File>,
        committed: bool,
        gate_held: bool,
    }

    pub struct ChildHandoff {
        token: [u8; HANDOFF_TOKEN_BYTES],
        ip: String,
        port: u16,
        stdin: std::io::Stdin,
        stderr: std::io::Stderr,
        parent_handle: usize,
        old_path: PathBuf,
    }

    pub fn prepare(ip: &str, port: u16, filename: &str, bytes: &[u8]) -> Result<PreparedUpdate, String> {
        if !UPDATE_IN_PROGRESS.swap(true, Ordering::AcqRel) {
            // Continue with the OS-level gate. The atomic only serializes callers
            // inside this process; the gate covers other agent processes.
        } else {
            return Err("another update is already in progress".into());
        }

        let mut gate_held = false;
        let result = (|| {
            if !sys::acquire_update_gate() {
                return Err("another update is already in progress".into());
            }
            gate_held = true;

            if ip.len() > MAX_HANDOFF_IP_BYTES || ip.contains(['\r', '\n']) {
                return Err("agent address is invalid for update handoff".into());
            }
            if port == 0 {
                return Err("agent port is invalid for update handoff".into());
            }
            if bytes.is_empty() || bytes.len() > MAX_UPDATE_BYTES {
                return Err("update payload size is invalid".into());
            }
            validate_pe(bytes)?;

            let normalized = normalize_filename(filename)?;
            let current = current_executable().map_err(|e| format!("{e}"))?;
            let directory = current
                .parent()
                .ok_or("current executable has no installation directory")?
                .to_path_buf();
            let target = directory.join(&normalized);
            let current_name = current
                .file_name()
                .ok_or("current executable has no filename")?;

            if target.file_name() != Some(OsStr::new(&normalized)) {
                return Err("invalid update target filename".into());
            }
            if same_path(&current, &target) {
                return Err("update filename must differ from the running executable because Windows locks the active image".into());
            }
            if target.exists() {
                return Err("update target already exists".into());
            }

            let old_name: Vec<u16> = current_name.encode_wide().collect();
            if old_name.is_empty() || old_name.len() > MAX_HANDOFF_OLD_NAME_UTF16 {
                return Err("current executable filename is too long".into());
            }

            let mut token = [0u8; HANDOFF_TOKEN_BYTES];
            let status = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    token.as_mut_ptr(),
                    token.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status != 0 || token.iter().all(|b| *b == 0) {
                return Err("failed to create update handoff token".into());
            }

            write_final_executable(&target, bytes)?;
            let (child_stdin, parent_to_child) = create_pipe()?;
            make_non_inheritable(&parent_to_child)?;
            let (parent_from_child, child_stderr) = create_pipe()?;
            make_non_inheritable(&parent_from_child)?;
            let mut prepared = PreparedUpdate {
                target_path: target,
                old_name,
                token,
                to_child: Some(parent_to_child),
                child_stdin: Some(child_stdin),
                from_child: Some(parent_from_child),
                child_stderr: Some(child_stderr),
                committed: false,
                gate_held,
            };

            let handshake = encode_handshake(&prepared.token, unsafe { GetCurrentProcessId() }, port, ip, &prepared.old_name)?;
            prepared
                .to_child
                .as_mut()
                .ok_or("missing update handoff pipe")?
                .write_all(&handshake)
                .map_err(|e| format!("failed to initialize update handoff: {e}"))?;
            prepared
                .to_child
                .as_mut()
                .ok_or("missing update handoff pipe")?
                .flush()
                .map_err(|e| format!("failed to flush update handoff: {e}"))?;
            Ok(prepared)
        })();

        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                if gate_held {
                    sys::release_update_gate();
                }
                UPDATE_IN_PROGRESS.store(false, Ordering::Release);
                Err(e)
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

        pub fn finish_after_disconnect(mut self) -> Result<(), String> {
            let child_stdin = self
                .child_stdin
                .take()
                .ok_or("update handoff input is unavailable")?;
            let child_stderr = self
                .child_stderr
                .take()
                .ok_or("update handoff status channel is unavailable")?;
            let mut child = Command::new(&self.target_path)
                .current_dir(self.target_path.parent().ok_or("update target has no directory")?)
                .stdin(Stdio::from(child_stdin))
                .stderr(Stdio::from(child_stderr))
                .stdout(Stdio::inherit())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .map_err(|e| format!("update launch failed: {e}"))?;

            let mut status = self
                .from_child
                .take()
                .ok_or("update handoff status reader is unavailable")?;
            if let Err(err) = wait_status(&mut status, HANDOFF_INIT, &self.token, Duration::from_millis(HANDOFF_INIT_TIMEOUT_MS)) {
                terminate_child(&mut child);
                return Err(format!("update IPC initialization failed: {err}"));
            }

            if let Err(err) = write_record_to_file(
                self.to_child.as_mut().ok_or("update handoff command pipe is unavailable")?,
                HANDOFF_RELEASE,
                &self.token,
            ) {
                terminate_child(&mut child);
                let _ = reacquire_mutex();
                return Err(format!("failed to send update release: {err}"));
            }

            if !sys::release_single() {
                terminate_child(&mut child);
                let _ = reacquire_mutex();
                return Err("failed to release the normal mutex for update handoff".into());
            }
            match wait_status(&mut status, HANDOFF_READY, &self.token, Duration::from_millis(HANDOFF_READY_TIMEOUT_MS)) {
                Ok(()) => {
                    if self.gate_held {
                        sys::release_update_gate();
                        self.gate_held = false;
                    }
                    self.committed = true;
                    UPDATE_IN_PROGRESS.store(false, Ordering::Release);
                    Ok(())
                }
                Err(err) => {
                    terminate_child(&mut child);
                    if !reacquire_mutex() {
                        return Err(format!("update successor failed and old mutex could not be reacquired: {err}"));
                    }
                    Err(format!("update successor did not become ready: {err}"))
                }
            }
        }

    }

    impl Drop for PreparedUpdate {
        fn drop(&mut self) {
            if !self.committed {
                if self.target_path.exists() {
                    let _ = fs::remove_file(&self.target_path);
                }
                if self.gate_held {
                    sys::release_update_gate();
                    self.gate_held = false;
                }
            }
            UPDATE_IN_PROGRESS.store(false, Ordering::Release);
        }
    }

    pub fn accept_handoff() -> Result<Option<ChildHandoff>, String> {
        let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if input.is_null() || unsafe { GetFileType(input) } != FILE_TYPE_PIPE {
            return Ok(None);
        }

        let mut peek = [0u8; HANDOFF_MAGIC.len()];
        let mut available = 0u32;
        let ok = unsafe {
            PeekNamedPipe(
                input,
                peek.as_mut_ptr(),
                peek.len() as u32,
                core::ptr::null_mut(),
                &mut available,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 || available < HANDOFF_MAGIC.len() as u32 {
            return Ok(None);
        }
        if &peek != HANDOFF_MAGIC {
            return Ok(None);
        }

        let mut stdin = std::io::stdin();
        let mut fixed = [0u8; 34];
        stdin
            .read_exact(&mut fixed)
            .map_err(|e| format!("failed to read update handoff header: {e}"))?;
        if &fixed[..8] != HANDOFF_MAGIC {
            return Err("invalid update handoff magic".into());
        }

        let mut token = [0u8; HANDOFF_TOKEN_BYTES];
        token.copy_from_slice(&fixed[8..24]);
        if token.iter().all(|b| *b == 0) {
            return Err("invalid update handoff token".into());
        }
        let parent_pid = u32::from_le_bytes(fixed[24..28].try_into().unwrap());
        let port = u16::from_le_bytes(fixed[28..30].try_into().unwrap());
        let ip_len = u16::from_le_bytes(fixed[30..32].try_into().unwrap()) as usize;
        let old_len = u16::from_le_bytes(fixed[32..34].try_into().unwrap()) as usize;
        if ip_len == 0 || ip_len > MAX_HANDOFF_IP_BYTES || old_len == 0 || old_len > MAX_HANDOFF_OLD_NAME_UTF16 * 2 {
            return Err("invalid update handoff metadata".into());
        }

        let mut ip_bytes = vec![0u8; ip_len];
        stdin
            .read_exact(&mut ip_bytes)
            .map_err(|e| format!("failed to read update address: {e}"))?;
        let ip = String::from_utf8(ip_bytes).map_err(|_| "invalid update address encoding".to_string())?;
        if ip.contains(['\r', '\n']) || port == 0 {
            return Err("invalid update address".into());
        }

        let mut old_bytes = vec![0u8; old_len];
        stdin
            .read_exact(&mut old_bytes)
            .map_err(|e| format!("failed to read old executable name: {e}"))?;
        if old_bytes.len() % 2 != 0 {
            return Err("invalid old executable name".into());
        }
        let old_words = old_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]));
        let old_os = OsString::from_wide(&old_words.collect::<Vec<_>>());
        let current = current_executable()?;
        let current_dir = current.parent().ok_or("update successor has no directory")?;
        let old_path = current_dir.join(&old_os);
        if same_path(&old_path, &current) || old_path.file_name() != Some(old_os.as_os_str()) {
            return Err("invalid old executable path in update handoff".into());
        }

        let parent_handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, parent_pid) };
        if parent_handle.is_null() {
            return Err("update parent process is no longer available".into());
        }
        if let Err(err) = verify_parent_image(parent_handle, &old_path) {
            unsafe { CloseHandle(parent_handle) };
            return Err(err);
        }

        let handoff = ChildHandoff {
            token,
            ip,
            port,
            stdin,
            stderr: std::io::stderr(),
            parent_handle: parent_handle as usize,
            old_path,
        };
        Ok(Some(handoff))
    }

    impl ChildHandoff {
        pub fn ip(&self) -> &str { &self.ip }
        pub fn port(&self) -> u16 { self.port }

        pub fn initialize_and_wait_for_release(&mut self) -> Result<(), String> {
            write_record(&mut self.stderr, HANDOFF_INIT, &self.token)?;
            wait_record_from_stdin(&mut self.stdin, HANDOFF_RELEASE, &self.token, Duration::from_millis(HANDOFF_RELEASE_TIMEOUT_MS))?;
            if !sys::acquire_successor_mutex(Duration::from_millis(20_000)) {
                write_record(&mut self.stderr, HANDOFF_FAIL, &self.token)?;
                return Err("update successor could not acquire the normal mutex".into());
            }
            Ok(())
        }

        pub fn signal_ready_and_schedule_cleanup(mut self) -> Result<(), String> {
            if let Err(err) = write_record(&mut self.stderr, HANDOFF_READY, &self.token) {
                let _ = sys::release_single();
                return Err(err);
            }
            let parent_handle = self.parent_handle;
            self.parent_handle = 0;
            let old_path = self.old_path.clone();
            thread::spawn(move || unsafe {
                let handle = parent_handle as Handle;
                let _ = WaitForSingleObject(handle, INFINITE);
                let _ = CloseHandle(handle);
                let wide: Vec<u16> = old_path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
                for _ in 0..40 {
                    if DeleteFileW(wide.as_ptr()) != 0 {
                        return;
                    }
                    Sleep(250);
                }
            });
            Ok(())
        }
    }

    impl Drop for ChildHandoff {
        fn drop(&mut self) {
            if self.parent_handle != 0 {
                unsafe { CloseHandle(self.parent_handle as Handle); }
                self.parent_handle = 0;
            }
        }
    }

    fn write_final_executable(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)
            .map_err(|e| format!("update write failed: {e}"))?;
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
    }

    fn create_pipe() -> Result<(std::fs::File, std::fs::File), String> {
        let mut read = core::ptr::null_mut();
        let mut write = core::ptr::null_mut();
        let mut sa = SecurityAttributes {
            length: core::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: core::ptr::null_mut(),
            inherit_handle: 1,
        };
        let ok = unsafe { CreatePipe(&mut read, &mut write, &mut sa, 0) };
        if ok == 0 || read.is_null() || write.is_null() {
            return Err("failed to create update IPC pipe".into());
        }
        let read_file = unsafe { std::fs::File::from_raw_handle(read as RawHandle) };
        let write_file = unsafe { std::fs::File::from_raw_handle(write as RawHandle) };
        Ok((read_file, write_file))
    }

    fn make_non_inheritable(file: &std::fs::File) -> Result<(), String> {
        if unsafe { SetHandleInformation(file.as_raw_handle() as Handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err("failed to protect update IPC parent handle".into());
        }
        Ok(())
    }

    fn encode_handshake(token: &[u8; HANDOFF_TOKEN_BYTES], pid: u32, port: u16, ip: &str, old_name: &[u16]) -> Result<Vec<u8>, String> {
        if ip.is_empty() || ip.len() > MAX_HANDOFF_IP_BYTES || old_name.is_empty() || old_name.len() > MAX_HANDOFF_OLD_NAME_UTF16 {
            return Err("update handoff metadata is too large".into());
        }
        let mut out = Vec::with_capacity(1100);
        out.extend_from_slice(HANDOFF_MAGIC);
        out.extend_from_slice(token);
        out.extend_from_slice(&pid.to_le_bytes());
        out.extend_from_slice(&port.to_le_bytes());
        out.extend_from_slice(&(ip.len() as u16).to_le_bytes());
        out.extend_from_slice(&((old_name.len() * 2) as u16).to_le_bytes());
        out.extend_from_slice(ip.as_bytes());
        for word in old_name {
            out.extend_from_slice(&word.to_le_bytes());
        }
        Ok(out)
    }

    fn current_executable() -> Result<PathBuf, String> {
        let mut size = 260usize;
        loop {
            let mut buffer = vec![0u16; size];
            let len = unsafe { GetModuleFileNameW(core::ptr::null_mut(), buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
            if len == 0 {
                return Err("failed to resolve current executable path".into());
            }
            if len < buffer.len() - 1 {
                let path = PathBuf::from(OsString::from_wide(&buffer[..len]));
                if path.is_absolute() {
                    return Ok(path);
                }
                return fs::canonicalize(&path).map_err(|e| format!("failed to resolve current executable path: {e}"));
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

    fn verify_parent_image(parent: Handle, expected: &Path) -> Result<(), String> {
        let mut size = 512u32;
        loop {
            let mut buf = vec![0u16; size as usize];
            let ok = unsafe { QueryFullProcessImageNameW(parent, 0, buf.as_mut_ptr(), &mut size) };
            if ok != 0 {
                let path = PathBuf::from(OsString::from_wide(&buf[..size as usize]));
                if same_path(&path, expected) {
                    return Ok(());
                }
                return Err("update handoff parent image does not match the running installation".into());
            }
            if size >= 32768 {
                return Err("failed to resolve update parent image path".into());
            }
            size *= 2;
        }
    }

    fn wait_status(file: &mut std::fs::File, expected: &str, token: &[u8; HANDOFF_TOKEN_BYTES], timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let mut buffer = Vec::with_capacity(64);
        loop {
            if Instant::now() >= deadline {
                return Err("update handoff timed out".into());
            }
            let handle = file.as_raw_handle() as Handle;
            let mut available = 0u32;
            let ok = unsafe { PeekNamedPipe(handle, core::ptr::null_mut(), 0, core::ptr::null_mut(), &mut available, core::ptr::null_mut()) };
            if ok == 0 {
                return Err("update IPC channel closed".into());
            }
            if available == 0 {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            let mut byte = [0u8; 1];
            file.read_exact(&mut byte).map_err(|e| format!("update IPC read failed: {e}"))?;
            if byte[0] == b'\n' {
                let record = String::from_utf8(buffer.clone()).map_err(|_| "invalid update IPC record".to_string())?;
                let wanted = format!("{expected} {}", hex_token(token));
                if record == wanted {
                    return Ok(());
                }
                if record == format!("{HANDOFF_FAIL} {}", hex_token(token)) {
                    return Err("successor reported handoff failure".into());
                }
                return Err(format!("unexpected update IPC record {record:?}"));
            }
            if buffer.len() >= 128 {
                return Err("update IPC record is too long".into());
            }
            buffer.push(byte[0]);
        }
    }

    fn write_record<W: Write>(writer: &mut W, kind: &str, token: &[u8; HANDOFF_TOKEN_BYTES]) -> Result<(), String> {
        write_record_to_file(writer, kind, token).map_err(|e| format!("update IPC write failed: {e}"))
    }

    fn write_record_to_file<W: Write>(writer: &mut W, kind: &str, token: &[u8; HANDOFF_TOKEN_BYTES]) -> io::Result<()> {
        writer.write_all(format!("{kind} {}\n", hex_token(token)).as_bytes())?;
        writer.flush()
    }

    fn wait_record_from_stdin(stdin: &mut std::io::Stdin, expected: &str, token: &[u8; HANDOFF_TOKEN_BYTES], timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let wanted = format!("{expected} {}", hex_token(token));
        let mut line = String::new();
        loop {
            if Instant::now() >= deadline {
                return Err("update release wait timed out".into());
            }
            let mut available = 0u32;
            let ok = unsafe { PeekNamedPipe(handle, core::ptr::null_mut(), 0, core::ptr::null_mut(), &mut available, core::ptr::null_mut()) };
            if ok == 0 {
                return Err("update handoff pipe closed".into());
            }
            if available == 0 {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            line.clear();
            stdin.read_line(&mut line).map_err(|e| format!("update release read failed: {e}"))?;
            if line.trim_end_matches(['\r', '\n']) == wanted {
                return Ok(());
            }
            return Err("invalid update release record".into());
        }
    }

    fn terminate_child(child: &mut Child) {
        if !child.try_wait().ok().flatten().is_some() {
            let _ = child.kill();
        }
        let _ = child.wait();
    }

    fn reacquire_mutex() -> bool {
        sys::acquire_successor_mutex(Duration::from_millis(10_000))
    }

    fn hex_token(token: &[u8; HANDOFF_TOKEN_BYTES]) -> String {
        token.iter().map(|b| format!("{b:02x}")).collect()
    }

}

#[cfg(windows)]
pub use windows_impl::{accept_handoff, prepare, ChildHandoff, PreparedUpdate};

#[cfg(not(windows))]
pub struct PreparedUpdate;

#[cfg(not(windows))]
impl PreparedUpdate {
    pub fn filename(&self) -> String { String::new() }
    pub fn finish_after_disconnect(self) -> Result<(), String> {
        Err("Update is supported only on Windows".into())
    }
}

#[cfg(not(windows))]
pub struct ChildHandoff;

#[cfg(not(windows))]
impl ChildHandoff {
    pub fn ip(&self) -> &str { "" }
    pub fn port(&self) -> u16 { 0 }
    pub fn initialize_and_wait_for_release(&mut self) -> Result<(), String> {
        Err("Update is supported only on Windows".into())
    }
    pub fn signal_ready_and_schedule_cleanup(self) -> Result<(), String> {
        Err("Update is supported only on Windows".into())
    }
}

#[cfg(not(windows))]
pub fn prepare(_: &str, _: u16, _: &str, _: &[u8]) -> Result<PreparedUpdate, String> {
    Err("Update is supported only on Windows".into())
}

#[cfg(not(windows))]
pub fn accept_handoff() -> Result<Option<ChildHandoff>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_normalization() {
        assert_eq!(normalize_filename("agent").unwrap(), "agent.exe");
        assert_eq!(normalize_filename("agent.exe").unwrap(), "agent.exe");
        assert_eq!(normalize_filename("agent.EXE").unwrap(), "agent.EXE");
    }

    #[test]
    fn filename_rejects_traversal_and_absolute_paths() {
        for name in ["..\\foo", "../../foo", "C:\\foo", "C:/foo", "\\\\server\\share\\foo"] {
            assert!(normalize_filename(name).is_err(), "accepted {name}");
        }
    }

    #[test]
    fn filename_rejects_windows_device_names() {
        for name in ["CON", "NUL.exe", "COM1", "LPT9.exe"] {
            assert!(normalize_filename(name).is_err(), "accepted {name}");
        }
    }

    #[test]
    fn base64_update_is_bounded_and_binary_safe() {
        let decoded = decode_b64_update("AAECAP8=").unwrap();
        assert_eq!(decoded, vec![0, 1, 2, 0, 255]);
        assert!(decode_b64_update(&"A".repeat(MAX_UPDATE_B64 + 1)).is_none());
    }

    #[test]
    fn minimal_pe_is_accepted_for_current_arch() {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        let machine = if cfg!(target_arch = "x86_64") { 0x8664u16 } else { 0x014cu16 };
        bytes[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
        bytes[0x46..0x48].copy_from_slice(&0u16.to_le_bytes());
        bytes[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes());
        bytes[0x58..0x5a].copy_from_slice(&0x20Bu16.to_le_bytes());
        bytes[0x90..0x94].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0x94..0x98].copy_from_slice(&0x200u32.to_le_bytes());
        assert!(validate_pe(&bytes).is_ok());
    }
}
