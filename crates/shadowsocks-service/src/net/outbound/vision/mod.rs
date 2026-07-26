//! Client-side XTLS-RPRX-Vision stream.
//!
//! The stream state machine and deframers are adapted from the MIT-licensed
//! `shoes` project; this module retains only the client-side functionality.
//! See `LICENSE-SHOES` at repository root.

#![allow(dead_code)]

mod sync_adapter;
mod tls_deframer;
mod tls_fuzzy_deframer;
mod tls_handshake_util;
mod vision_filter;
mod vision_pad;
mod vision_stream;
mod vision_unpad;

pub(super) use vision_stream::VisionStream;

struct ParsedServerHello {
    cipher_suite: u16,
    is_tls13: bool,
}

/// Minimal strict parser for the fields Vision needs from a TLS ServerHello.
fn parse_server_hello(record: &[u8]) -> std::io::Result<ParsedServerHello> {
    const RECORD_HEADER: usize = 5;
    const HANDSHAKE_HEADER: usize = 4;
    if record.len() < 47 || record[0] != 0x16 || record[1..3] != [0x03, 0x03] || record[5] != 0x02 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid TLS ServerHello",
        ));
    }
    let message_len = ((record[6] as usize) << 16) | ((record[7] as usize) << 8) | record[8] as usize;
    if record.len() < RECORD_HEADER + HANDSHAKE_HEADER + message_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated TLS ServerHello",
        ));
    }

    let session_len_offset = 5 + 4 + 2 + 32;
    let session_len = record[session_len_offset] as usize;
    if session_len > 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid TLS session id",
        ));
    }
    let cipher_offset = session_len_offset + 1 + session_len;
    if cipher_offset + 3 > record.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated TLS ServerHello",
        ));
    }
    let cipher_suite = u16::from_be_bytes([record[cipher_offset], record[cipher_offset + 1]]);
    let extensions_len_offset = cipher_offset + 3;
    let mut is_tls13 = false;
    if extensions_len_offset + 2 <= record.len() {
        let extensions_len =
            u16::from_be_bytes([record[extensions_len_offset], record[extensions_len_offset + 1]]) as usize;
        let mut cursor = extensions_len_offset + 2;
        let end = cursor
            .checked_add(extensions_len)
            .filter(|end| *end <= record.len())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated ServerHello extensions")
            })?;
        while cursor + 4 <= end {
            let kind = u16::from_be_bytes([record[cursor], record[cursor + 1]]);
            let len = u16::from_be_bytes([record[cursor + 2], record[cursor + 3]]) as usize;
            cursor += 4;
            if cursor + len > end {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated ServerHello extension",
                ));
            }
            if kind == 0x002b && len == 2 && record[cursor..cursor + 2] == [0x03, 0x04] {
                is_tls13 = true;
            }
            cursor += len;
        }
    }
    Ok(ParsedServerHello { cipher_suite, is_tls13 })
}
