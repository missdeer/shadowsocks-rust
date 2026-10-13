// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::HashMap, time::Duration};

use obfs_local::{
    config::{self, Config},
    relay,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

fn configuration(mode: &str) -> Config {
    let matches = config::command()
        .try_get_matches_from([
            "obfs-local",
            "-s",
            "127.0.0.1",
            "-p",
            "443",
            "-l",
            "12345",
            "--obfs",
            mode,
        ])
        .unwrap();
    Config::from_matches(&matches, &HashMap::new()).unwrap()
}

async fn exchange(mode: &'static str) {
    let remote_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote_listener.local_addr().unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let config = configuration(mode);
    let server = tokio::spawn(async move {
        let (mut stream, _) = remote_listener.accept().await.unwrap();
        let mut wire = Vec::new();
        if mode == "http" {
            loop {
                wire.push(stream.read_u8().await.unwrap());
                if wire.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert!(wire.starts_with(b"GET / HTTP/1.1\r\n"));
            assert!(
                wire.windows(b"Content-Length: 5".len())
                    .any(|w| w == b"Content-Length: 5")
            );
            let mut payload = [0; 5];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"first");
        } else {
            let mut header = [0; 5];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[..3], &[0x16, 0x03, 0x01]);
            wire.resize(u16::from_be_bytes([header[3], header[4]]) as usize, 0);
            stream.read_exact(&mut wire).await.unwrap();
            assert_eq!(&wire[133..137], &[0, 0x23, 0, 5]);
            assert_eq!(&wire[137..142], b"first");
        }
        let fixture: &[u8] = if mode == "http" {
            include_bytes!("fixtures/http-response.bin")
        } else {
            include_bytes!("fixtures/tls-response.bin")
        };
        for chunk in fixture.chunks(3) {
            stream.write_all(chunk).await.unwrap();
        }
        let mut second = vec![0; if mode == "http" { 6 } else { 11 }];
        stream.read_exact(&mut second).await.unwrap();
        if mode == "tls" {
            assert_eq!(&second[..5], &[0x17, 3, 3, 0, 6]);
            assert_eq!(&second[5..], b"second");
        } else {
            assert_eq!(&second, b"second");
        }
        // The client half-closes but must still receive the final response.
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        if mode == "tls" {
            stream.write_all(&[0x17, 3, 3, 0, 4]).await.unwrap();
        }
        stream.write_all(b"last").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let proxy = tokio::spawn(async move {
        let (local, _) = local_listener.accept().await.unwrap();
        relay::relay(local, remote_addr, &config).await.unwrap();
    });
    let mut client = TcpStream::connect(local_addr).await.unwrap();
    client.write_all(b"first").await.unwrap();
    let mut expected = b"server-first\0\xff".to_vec();
    expected.extend((0u8..=255).cycle().take(2048));
    let mut actual = vec![0; expected.len()];
    client.read_exact(&mut actual).await.unwrap();
    assert_eq!(actual, expected);
    client.write_all(b"second").await.unwrap();
    client.shutdown().await.unwrap();
    let mut last = Vec::new();
    client.read_to_end(&mut last).await.unwrap();
    assert_eq!(last, b"last");
    server.await.unwrap();
    proxy.await.unwrap();
}

#[tokio::test]
async fn http_and_tls_relay_preserve_payloads_and_half_close() {
    timeout(Duration::from_secs(5), exchange("http")).await.unwrap();
    timeout(Duration::from_secs(5), exchange("tls")).await.unwrap();
}

#[tokio::test]
async fn empty_startup_probe_does_not_connect_upstream() {
    let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (local, _) = listener.accept().await.unwrap();
    client.shutdown().await.unwrap();
    relay::relay(local, remote.local_addr().unwrap(), &configuration("http"))
        .await
        .unwrap();
    assert!(timeout(Duration::from_millis(20), remote.accept()).await.is_err());
}

#[tokio::test]
async fn silent_remote_times_out_and_closes_local_socket() {
    let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (local, _) = listener.accept().await.unwrap();
    let mut config = configuration("http");
    config.timeout = Duration::from_millis(50);
    let addr = remote.local_addr().unwrap();
    let proxy = tokio::spawn(async move { relay::relay(local, addr, &config).await });
    client.write_all(b"first").await.unwrap();
    let (_upstream, _) = remote.accept().await.unwrap();
    let result = timeout(Duration::from_secs(2), proxy).await.unwrap().unwrap();
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(
        client.read_u8().await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}
