mod id;
mod msg;
mod net;
mod power;

use std::env;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows_sys::Win32::System::Threading::CreateMutexW;

struct MutexGuard(HANDLE);

impl Drop for MutexGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0); }
        }
    }
}

fn main() {
    let _mutex = match single() {
        Some(guard) => guard,
        None => {
            println!("{}", msg::OUT_RUNNING);
            return;
        }
    };

    let target = match args() {
        Ok(target) => target,
        Err(_) => {
            println!("{}", msg::OUT_USAGE);
            return;
        }
    };

    if net::run(&target).is_err() {
        println!("{}", msg::OUT_RECONNECT);
    }
}

fn single() -> Option<MutexGuard> {
    let name: Vec<u16> = msg::MUTEX.encode_utf16().chain([0]).collect();
    let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 1, name.as_ptr()) };
    if handle.is_null() || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        if !handle.is_null() {
            unsafe { CloseHandle(handle); }
        }
        return None;
    }
    Some(MutexGuard(handle))
}

fn args() -> Result<net::Target, ()> {
    let mut ip = msg::DEFAULT_IP.to_owned();
    let mut port = msg::DEFAULT_PORT;
    let mut it = env::args().skip(1);

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--ip" => ip = it.next().ok_or(())?,
            "--port" => port = it.next().ok_or(())?.parse().map_err(|_| ())?,
            _ => return Err(()),
        }
    }

    if ip.trim().is_empty() || port == 0 {
        return Err(());
    }

    Ok(net::Target { ip, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        assert_eq!(msg::DEFAULT_IP, "127.0.0.1");
        assert_eq!(msg::DEFAULT_PORT, 4793);
    }

    #[test]
    fn fingerprint_matches_python_contract() {
        assert_eq!(
            id::fingerprint_from_machine_id("TEST-MACHINE-GUID"),
            "85b8e4e673e922677b1979109a3f24ea6080f12f6440c604fe8025a684886779"
        );
    }

    #[test]
    fn telemetry_matches_server_shape() {
        assert_eq!(net::test_telemetry().split('|').count(), 16);
    }

    #[test]
    fn block_is_not_registered() {
        let commands = [
            msg::SLEEP,
            msg::HIBERNATE,
            msg::RESTART,
            msg::SHUTDOWN,
            msg::RECONNECT,
            msg::CLOSE,
        ];
        assert!(!commands.contains(&msg::BLOCK));
    }
}
