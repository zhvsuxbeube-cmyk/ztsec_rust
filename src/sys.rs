#[cfg(windows)]
mod win {
    use std::{
        ffi::OsStr,
        iter,
        os::windows::ffi::OsStrExt,
        ptr,
        sync::atomic::{AtomicUsize, Ordering},
        thread,
        time::{Duration, Instant},
    };

    type Handle = *mut core::ffi::c_void;
    type Status = i32;

    static SINGLE_HANDLE: AtomicUsize = AtomicUsize::new(0);
    static UPDATE_GATE_HANDLE: AtomicUsize = AtomicUsize::new(0);

    #[repr(C)]
    struct Unicode {
        len: u16,
        max: u16,
        buf: *mut u16,
    }

    #[repr(C)]
    struct Attrs {
        len: u32,
        root: Handle,
        name: *mut Unicode,
        attrs: u32,
        sd: *mut core::ffi::c_void,
        qos: *mut core::ffi::c_void,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateMutant(
            handle: *mut Handle,
            access: u32,
            attrs: *mut Attrs,
            owner: u8,
        ) -> Status;
        fn NtClose(handle: Handle) -> Status;
        fn NtReleaseMutant(handle: Handle, previous_count: *mut i32) -> Status;
        fn RtlAdjustPrivilege(
            privilege: u32,
            enable: u8,
            thread: u8,
            previous: *mut u8,
        ) -> Status;
        fn NtSetSystemPowerState(action: i32, state: i32, flags: u32) -> Status;
        fn NtShutdownSystem(action: i32) -> Status;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateMutexW(attrs: *mut core::ffi::c_void, owner: i32, name: *const u16) -> Handle;
        fn GetLastError() -> u32;
        fn OpenMutexW(access: u32, inherit: i32, name: *const u16) -> Handle;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn ReleaseMutex(handle: Handle) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    const OK: Status = 0;
    const ACCESS: u32 = 0x001F0001;
    const SHUTDOWN: u32 = 19;

    const UPDATE_GATE: &str = r"Global\ZTSecurity.ztsec_agent.update";
    const MUTEX_SYNCHRONIZE: u32 = 0x0010_0000;
    const MUTEX_MODIFY_STATE: u32 = 0x0000_0001;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    const WAIT_ABANDONED: u32 = 0x0000_0080;
    const SLEEP: i32 = 2;
    const HIBERNATE: i32 = 3;
    const REBOOT: i32 = 1;
    const POWER_OFF: i32 = 2;
    const S3: i32 = 4;
    const S4: i32 = 5;

    fn create_single_mutant(owner: u8) -> Option<Handle> {
        let wide: Vec<u16> = OsStr::new(crate::text::MUTEX)
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        let mut name = Unicode {
            len: ((wide.len() - 1) * 2) as u16,
            max: (wide.len() * 2) as u16,
            buf: wide.as_ptr() as *mut u16,
        };
        let mut attrs = Attrs {
            len: core::mem::size_of::<Attrs>() as u32,
            root: ptr::null_mut(),
            name: &mut name,
            attrs: 0,
            sd: ptr::null_mut(),
            qos: ptr::null_mut(),
        };
        let mut handle: Handle = ptr::null_mut();
        let status = unsafe { NtCreateMutant(&mut handle, ACCESS, &mut attrs, owner) };
        if status == OK {
            Some(handle)
        } else {
            if !handle.is_null() {
                unsafe { NtClose(handle); }
            }
            None
        }
    }

    pub fn single() -> bool {
        if update_gate_held() {
            return false;
        }
        let Some(handle) = create_single_mutant(1) else {
            return false;
        };
        SINGLE_HANDLE.store(handle as usize, Ordering::Release);
        true
    }

    pub fn release_single() -> bool {
        let handle = SINGLE_HANDLE.swap(0, Ordering::AcqRel) as Handle;
        if handle.is_null() {
            return true;
        }
        let status = unsafe { NtReleaseMutant(handle, ptr::null_mut()) };
        let close_status = unsafe { NtClose(handle) };
        status == OK && close_status == OK
    }

    pub fn acquire_successor_mutex(timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if SINGLE_HANDLE.load(Ordering::Acquire) != 0 {
                return true;
            }
            if let Some(handle) = create_single_mutant(1) {
                SINGLE_HANDLE.store(handle as usize, Ordering::Release);
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    pub fn acquire_update_gate() -> bool {
        if UPDATE_GATE_HANDLE.load(Ordering::Acquire) != 0 {
            return false;
        }
        let wide: Vec<u16> = OsStr::new(UPDATE_GATE)
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        let handle = unsafe { CreateMutexW(ptr::null_mut(), 1, wide.as_ptr()) };
        if handle.is_null() {
            return false;
        }
        let already_exists = unsafe { GetLastError() } == 183;
        if already_exists {
            let wait = unsafe { WaitForSingleObject(handle, 0) };
            if !matches!(wait, WAIT_OBJECT_0 | WAIT_ABANDONED) {
                unsafe { CloseHandle(handle); }
                return false;
            }
        }
        UPDATE_GATE_HANDLE.store(handle as usize, Ordering::Release);
        true
    }

    pub fn release_update_gate() {
        let handle = UPDATE_GATE_HANDLE.swap(0, Ordering::AcqRel) as Handle;
        if handle.is_null() {
            return;
        }
        unsafe {
            let _ = ReleaseMutex(handle);
            let _ = CloseHandle(handle);
        }
    }

    pub fn update_gate_held() -> bool {
        let wide: Vec<u16> = OsStr::new(UPDATE_GATE)
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        let handle = unsafe { OpenMutexW(MUTEX_SYNCHRONIZE | MUTEX_MODIFY_STATE, 0, wide.as_ptr()) };
        if handle.is_null() {
            return false;
        }
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        match wait {
            WAIT_TIMEOUT => {
                unsafe { CloseHandle(handle); }
                true
            }
            WAIT_OBJECT_0 | WAIT_ABANDONED => {
                unsafe {
                    let _ = ReleaseMutex(handle);
                    let _ = CloseHandle(handle);
                }
                false
            }
            _ => {
                unsafe { CloseHandle(handle); }
                true
            }
        }
    }

    fn privilege() -> bool {
        let mut previous = 0u8;
        unsafe { RtlAdjustPrivilege(SHUTDOWN, 1, 0, &mut previous) == OK }
    }

    fn power(action: i32, state: i32) -> bool {
        privilege() && unsafe { NtSetSystemPowerState(action, state, 0) == OK }
    }

    pub fn command(cmd: &str) -> bool {
        match cmd {
            crate::text::SLEEP => power(SLEEP, S3),
            crate::text::HIBERNATE => power(HIBERNATE, S4),
            crate::text::RESTART if privilege() => unsafe { NtShutdownSystem(REBOOT) == OK },
            crate::text::SHUTDOWN if privilege() => {
                unsafe { NtShutdownSystem(POWER_OFF) == OK }
            }
            _ => false,
        }
    }
}

#[cfg(not(windows))]
mod win {
    use std::time::Duration;

    pub fn single() -> bool { true }
    pub fn release_single() -> bool { true }
    pub fn acquire_successor_mutex(_: Duration) -> bool { true }
    pub fn acquire_update_gate() -> bool { true }
    pub fn release_update_gate() {}
    pub fn update_gate_held() -> bool { false }

    pub fn command(_: &str) -> bool { false }
}

pub use win::{acquire_successor_mutex, acquire_update_gate, command, release_single, release_update_gate, single};
