// SPDX-License-Identifier: GPL-3.0-or-later
// Wire layouts ported from simple-obfs obfs_http.c / obfs_tls.c.
// Original copyright (C) 2013-2016 Max Lv <max.c.lv@gmail.com>.

use std::{io, time::SystemTime};

use base64::{Engine, engine::general_purpose::STANDARD};
use rand::RngExt;

/// Maximum application record accepted by simple-obfs's TLS decoder.
pub const MAX_RECORD: usize = 16384;
const MAX_HTTP_HEADER: usize = 65536;
const CIPHERS: &[u8] = &[
    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0,
    0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09,
    0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
];
const OTHER_EXTENSIONS: &[u8] = &[
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00,
    0x19, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02,
    0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02,
    0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Http,
    Tls,
}

impl Mode {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "http" => Ok(Self::Http),
            "tls" => Ok(Self::Tls),
            _ => Err(invalid("obfs must be http or tls")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Parameters {
    pub mode: Mode,
    pub host: String,
    pub port: u16,
    pub uri: String,
    pub method: String,
}

/// Each connection has independent send/receive state.
pub struct Encoder {
    parameters: Parameters,
    started: bool,
}

impl Encoder {
    pub fn new(parameters: Parameters) -> Self {
        Self {
            parameters,
            started: false,
        }
    }

    pub fn encode(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.is_empty() {
            return Ok(Vec::new());
        }
        let result = match (self.parameters.mode, self.started) {
            (Mode::Http, false) => self.http_request(payload),
            (Mode::Http, true) => payload.to_vec(),
            (Mode::Tls, false) => self.client_hello(payload)?,
            (Mode::Tls, true) => {
                let mut records = Vec::with_capacity(payload.len() + 5 * payload.len().div_ceil(MAX_RECORD));
                for chunk in payload.chunks(MAX_RECORD) {
                    records.extend_from_slice(&[0x17, 0x03, 0x03]);
                    records.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                    records.extend_from_slice(chunk);
                }
                records
            }
        };
        self.started = true;
        Ok(result)
    }

    fn http_request(&self, payload: &[u8]) -> Vec<u8> {
        let p = &self.parameters;
        let host = if p.port == 80 {
            p.host.clone()
        } else {
            format!("{}:{}", p.host, p.port)
        };
        let key = STANDARD.encode(rand::random::<[u8; 16]>());
        let major = rand::rng().random_range(0..51);
        let minor = rand::rng().random_range(0..2);
        let header = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.{}.{}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: {}\r\nContent-Length: {}\r\n\r\n",
            p.method,
            p.uri,
            host,
            major,
            minor,
            key,
            payload.len()
        );
        let mut result = header.into_bytes();
        result.extend_from_slice(payload);
        result
    }

    fn client_hello(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        // The C implementation uses a 16-bit handshake length and puts the
        // encrypted Shadowsocks prefix in the first extension (session ticket).
        let host = self.parameters.host.as_bytes();
        let total = 138 + 4 + payload.len() + 9 + host.len() + OTHER_EXTENSIONS.len();
        if total - 5 > u16::MAX as usize {
            return Err(invalid("TLS ClientHello is too large"));
        }
        let mut result = Vec::with_capacity(total);
        result.extend_from_slice(&[0x16, 0x03, 0x01]);
        result.extend_from_slice(&((total - 5) as u16).to_be_bytes());
        result.extend_from_slice(&[0x01, 0x00]);
        result.extend_from_slice(&((total - 9) as u16).to_be_bytes());
        result.extend_from_slice(&[0x03, 0x03]);
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        result.extend_from_slice(&timestamp.to_be_bytes());
        result.extend_from_slice(&rand::random::<[u8; 28]>());
        result.push(32);
        result.extend_from_slice(&rand::random::<[u8; 32]>());
        result.extend_from_slice(&(CIPHERS.len() as u16).to_be_bytes());
        result.extend_from_slice(CIPHERS);
        result.extend_from_slice(&[0x01, 0x00]);
        result.extend_from_slice(&((total - 138) as u16).to_be_bytes());
        result.extend_from_slice(&[0x00, 0x23]);
        result.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        result.extend_from_slice(payload);
        result.extend_from_slice(&[0x00, 0x00]);
        result.extend_from_slice(&((host.len() + 5) as u16).to_be_bytes());
        result.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        result.push(0);
        result.extend_from_slice(&(host.len() as u16).to_be_bytes());
        result.extend_from_slice(host);
        result.extend_from_slice(OTHER_EXTENSIONS);
        Ok(result)
    }
}

enum ReceiveState {
    HttpHeader,
    Raw,
    ServerHello,
    ChangeCipherSpec,
    EncryptedHandshake,
    ApplicationHeader,
    Body { remaining: usize },
}

/// Incrementally strips HTTP headers or TLS records, including split headers
/// and payloads, with bounded buffering and validation of record lengths.
pub struct Decoder {
    state: ReceiveState,
    pending: Vec<u8>,
}

impl Decoder {
    pub fn new(mode: Mode) -> Self {
        Self {
            state: match mode {
                Mode::Http => ReceiveState::HttpHeader,
                Mode::Tls => ReceiveState::ServerHello,
            },
            pending: Vec::new(),
        }
    }

    pub fn decode(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        self.pending.extend_from_slice(input);
        let mut output = Vec::new();
        let mut cursor = 0;
        loop {
            let data = &self.pending[cursor..];
            match &mut self.state {
                ReceiveState::HttpHeader => {
                    if let Some(end) = data.windows(4).position(|part| part == b"\r\n\r\n") {
                        if end + 4 > MAX_HTTP_HEADER {
                            return Err(invalid("HTTP obfs header is too large"));
                        }
                        cursor += end + 4;
                        self.state = ReceiveState::Raw;
                    } else {
                        if data.len() > MAX_HTTP_HEADER {
                            return Err(invalid("HTTP obfs header is too large"));
                        }
                        break;
                    }
                }
                ReceiveState::Raw => {
                    output.extend_from_slice(data);
                    cursor = self.pending.len();
                    break;
                }
                ReceiveState::ServerHello => {
                    if data.len() < 5 {
                        break;
                    }
                    // simple-obfs's server hello is a fixed 96-byte record.
                    if data[..3] != [0x16, 0x03, 0x01] || data[3..5] != [0x00, 0x5b] {
                        return Err(invalid("invalid obfs TLS ServerHello"));
                    }
                    if data.len() < 96 {
                        break;
                    }
                    cursor += 96;
                    self.state = ReceiveState::ChangeCipherSpec;
                }
                ReceiveState::ChangeCipherSpec => {
                    if data.len() < 6 {
                        break;
                    }
                    if data[..6] != [0x14, 0x03, 0x03, 0x00, 0x01, 0x01] {
                        return Err(invalid("invalid obfs TLS ChangeCipherSpec"));
                    }
                    cursor += 6;
                    self.state = ReceiveState::EncryptedHandshake;
                }
                ReceiveState::EncryptedHandshake | ReceiveState::ApplicationHeader => {
                    if data.len() < 5 {
                        break;
                    }
                    let handshake = matches!(self.state, ReceiveState::EncryptedHandshake);
                    let content_type = if handshake { 0x16 } else { 0x17 };
                    if data[..3] != [content_type, 0x03, 0x03] {
                        return Err(invalid("invalid obfs TLS record header"));
                    }
                    let remaining = u16::from_be_bytes([data[3], data[4]]) as usize;
                    if remaining > MAX_RECORD {
                        return Err(invalid("obfs TLS record exceeds 16384 bytes"));
                    }
                    cursor += 5;
                    self.state = ReceiveState::Body { remaining };
                }
                ReceiveState::Body { remaining } => {
                    let count = (*remaining).min(data.len());
                    output.extend_from_slice(&data[..count]);
                    cursor += count;
                    *remaining -= count;
                    if *remaining == 0 {
                        self.state = ReceiveState::ApplicationHeader;
                    } else {
                        break;
                    }
                }
            }
        }
        self.pending.drain(..cursor);
        Ok(output)
    }

    pub fn finish(&self) -> io::Result<()> {
        // An empty connection is legitimate (SIP003 startup probes do this).
        if self.pending.is_empty()
            && matches!(
                self.state,
                ReceiveState::HttpHeader
                    | ReceiveState::Raw
                    | ReceiveState::ServerHello
                    | ReceiveState::ApplicationHeader
            )
        {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated obfs response"))
        }
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
