// SPDX-License-Identifier: GPL-3.0-or-later

use obfs_local::protocol::{Decoder, Encoder, MAX_RECORD, Mode, Parameters};

fn parameters(mode: Mode) -> Parameters {
    Parameters {
        mode,
        host: "cloudfront.net".into(),
        port: 443,
        uri: "/".into(),
        method: "GET".into(),
    }
}

fn payload() -> Vec<u8> {
    (0u8..=255).cycle().take(2048).collect()
}

#[test]
fn tls_request_matches_original_c_client() {
    let expected = include_bytes!("fixtures/tls-request.bin");
    let mut actual = Encoder::new(parameters(Mode::Tls)).encode(&payload()).unwrap();
    // Only timestamp, client random and session ID vary between executions.
    actual[11..43].copy_from_slice(&expected[11..43]);
    actual[44..76].copy_from_slice(&expected[44..76]);
    assert_eq!(actual, expected);
}

fn normalize_http(input: &[u8]) -> Vec<u8> {
    let split = input.windows(4).position(|part| part == b"\r\n\r\n").unwrap() + 4;
    let mut result = Vec::new();
    for line in std::str::from_utf8(&input[..split]).unwrap().split("\r\n") {
        if !line.starts_with("User-Agent:") && !line.starts_with("Sec-WebSocket-Key:") {
            result.extend_from_slice(line.as_bytes());
            result.extend_from_slice(b"\r\n");
        }
    }
    result.extend_from_slice(&input[split..]);
    result
}

#[test]
fn http_request_matches_original_c_client_and_only_wraps_first_write() {
    let mut encoder = Encoder::new(parameters(Mode::Http));
    let actual = encoder.encode(&payload()).unwrap();
    assert_eq!(
        normalize_http(&actual),
        normalize_http(include_bytes!("fixtures/http-request.bin"))
    );
    assert_eq!(encoder.encode(b"second write").unwrap(), b"second write");
}

#[test]
fn original_c_responses_decode_under_arbitrary_fragmentation() {
    let mut expected = b"server-first\0\xff".to_vec();
    expected.extend_from_slice(&payload());
    for (mode, fixture) in [
        (Mode::Http, include_bytes!("fixtures/http-response.bin").as_slice()),
        (Mode::Tls, include_bytes!("fixtures/tls-response.bin").as_slice()),
    ] {
        for chunk_size in [1, 2, 3, 4, 5, 6, 7, 31, 96, 107, 2048, fixture.len()] {
            let mut decoder = Decoder::new(mode);
            let mut actual = Vec::new();
            for chunk in fixture.chunks(chunk_size) {
                actual.extend_from_slice(&decoder.decode(chunk).unwrap());
            }
            decoder.finish().unwrap();
            assert_eq!(actual, expected, "{mode:?}, fragments={chunk_size}");
        }
    }
}

#[test]
fn tls_application_records_split_large_writes_and_validate_lengths() {
    let mut encoder = Encoder::new(parameters(Mode::Tls));
    encoder.encode(b"first").unwrap();
    let data = vec![0x42; MAX_RECORD * 2 + 1];
    let wire = encoder.encode(&data).unwrap();
    assert_eq!(wire.len(), data.len() + 15);
    let mut decoder = Decoder::new(Mode::Tls);
    decoder.decode(include_bytes!("fixtures/tls-response.bin")).unwrap();
    let mut actual = Vec::new();
    for chunk in wire.chunks(3) {
        actual.extend_from_slice(&decoder.decode(chunk).unwrap());
    }
    assert_eq!(actual, data);
    decoder.finish().unwrap();
    assert!(decoder.decode(&[0x17, 0x03, 0x03, 0x40, 0x01]).is_err());
}

#[test]
fn rejects_truncated_and_malformed_responses_without_panicking() {
    let fixture = include_bytes!("fixtures/tls-response.bin");
    for end in [1, 4, 5, 95, 96, 101, 102, 106, 107, 110, fixture.len() - 1] {
        let mut decoder = Decoder::new(Mode::Tls);
        decoder.decode(&fixture[..end]).unwrap();
        assert!(decoder.finish().is_err(), "truncation at {end}");
    }
    let mut decoder = Decoder::new(Mode::Tls);
    assert!(decoder.decode(b"HTTP/1.1 200 OK").is_err());
    let mut decoder = Decoder::new(Mode::Http);
    assert!(decoder.decode(&vec![b'A'; 65537]).is_err());
}

#[test]
fn empty_startup_probe_does_not_advance_encoder_or_decoder() {
    let mut encoder = Encoder::new(parameters(Mode::Tls));
    assert!(encoder.encode(b"").unwrap().is_empty());
    assert_eq!(encoder.encode(b"payload").unwrap()[0], 0x16);
    for mode in [Mode::Http, Mode::Tls] {
        Decoder::new(mode).finish().unwrap();
    }
}
