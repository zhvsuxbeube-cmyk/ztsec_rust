#[cfg(windows)]
mod win {
    use std::{
        ffi::OsStr,
        iter,
        os::windows::ffi::OsStrExt,
        sync::atomic::{AtomicUsize, Ordering},
        thread,
        time::{Duration, Instant},
    };

    type Handle = *mut core::ffi::c_void;
    type Status = i32;

    static SINGLE_HANDLE: AtomicUsize = AtomicUsize::new(0);

    #[link(name = "ntdll")]
    unsafe extern "system" {
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
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn ReleaseMutex(handle: Handle) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    const OK: Status = 0;
    const SHUTDOWN: u32 = 19;

    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    const WAIT_ABANDONED: u32 = 0x0000_0080;
    const ERROR_ALREADY_EXISTS: u32 = 183;
    const SLEEP: i32 = 2;
    const HIBERNATE: i32 = 3;
    const REBOOT: i32 = 1;
    const POWER_OFF: i32 = 2;
    const S3: i32 = 4;
    const S4: i32 = 5;

    fn mutex_name() -> Vec<u16> {
        OsStr::new(crate::text::MUTEX)
            .encode_wide()
            .chain(iter::once(0))
            .collect()
    }

    fn create_single_mutex() -> Option<Handle> {
        let wide = mutex_name();
        let handle = unsafe { CreateMutexW(core::ptr::null_mut(), 1, wide.as_ptr()) };
        if handle.is_null() {
            return None;
        }
        if unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
            return Some(handle);
        }

        // For an existing named mutex, explicitly perform a zero-time ownership
        // attempt. If CreateMutexW supplied a usable handle but ownership is
        // unavailable, close it rather than ever blocking the caller.
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        match wait {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Some(handle),
            WAIT_TIMEOUT => {
                unsafe { CloseHandle(handle); }
                None
            }
            _ => {
                unsafe { CloseHandle(handle); }
                None
            }
        }
    }

    pub fn single() -> bool {
        let Some(handle) = create_single_mutex() else {
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
        let released = unsafe { ReleaseMutex(handle) } != 0;
        let closed = unsafe { CloseHandle(handle) } != 0;
        released && closed
    }

    pub fn acquire_successor_mutex(timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if SINGLE_HANDLE.load(Ordering::Acquire) != 0 {
                return true;
            }
            if let Some(handle) = create_single_mutex() {
                SINGLE_HANDLE.store(handle as usize, Ordering::Release);
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(25));
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
    pub fn command(_: &str) -> bool { false }
}

pub use win::{acquire_successor_mutex, command, release_single, single};
