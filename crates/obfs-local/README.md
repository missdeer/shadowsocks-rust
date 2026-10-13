# obfs-local (Rust)

Client-only replacement for simple-obfs `obfs-local`, supporting its HTTP and
TLS obfuscation formats, command-line options, JSON configuration, and SIP003
environment variables. It does not use libev, MinGW, or an external TLS library.
TLS mode implements simple-obfs's imitation TLS framing, not a TLS session.

```powershell
cargo build -p obfs-local --release
.\target\release\obfs-local.exe -s server.example.com -p 443 -l 1081 --obfs http --obfs-host example.com
```

`sslocal` can use the executable directly through its existing `plugin` field:

```json
{
    "plugin": "D:/Projects/shadowsocks-rust/target/release/obfs-local.exe",
    "plugin_opts": "obfs=http;obfs-host=example.com"
}
```

The local listener is a raw TCP tunnel, not a SOCKS/HTTP proxy. Connect the
Shadowsocks client to it, or let `sslocal` launch it using SIP003.

## Compatible interfaces

Short options: `-s` (repeatable remote), `-p`, `-l`, `-b`, `-t`, `-c`, `-i`, `-a`,
`-f`, `-n`, `-v`, `-6`, `-h`. Long options: `--obfs`, `--obfs-host`, `--obfs-uri`,
`--http-method`, `--fast-open`, `--mptcp`, `--help`.

SIP003 reads `SS_REMOTE_HOST`, `SS_REMOTE_PORT`, `SS_LOCAL_HOST`, `SS_LOCAL_PORT`,
and `SS_PLUGIN_OPTIONS`. Multiple remote hosts are separated with `|`. Plugin
options support escaped `;`, `=`, and `\`. Command-line values override environment
values; JSON supplies remaining values. `-s` appends to environment-provided hosts,
as in the original client. Unknown SIP003 options and unrelated JSON fields are ignored.

JSON keys: `server` (string or array), `server_port`, `local_address`, `local_port`,
`timeout`, `obfs`, `obfs_host`, `obfs_uri`, `http_method`, `fast_open`, `mptcp`,
`user`, `nofile`. Server array entries accept `host:port` and `[IPv6]:port`.
Numeric ports may also be strings. Defaults are `127.0.0.1`, timeout 600 seconds,
host `cloudfront.net`, method `GET`, and URI `/`. Mode and ports are required.

TCP Fast Open uses `tokio-tfo` on Windows/Linux/macOS/FreeBSD. `-i` binds an
outbound interface on Linux; `--mptcp` attempts Linux MPTCP, with TCP fallback.
Unix supports `-a` privilege dropping, `-n` resource limits, `-f` daemonization,
SIGINT/SIGTERM/SIGUSR1 shutdown, and parent-process monitoring. Windows accepts
`-a`, `-n`, `-f`, `-i` and `--mptcp` without applying Unix-specific operations,
matching the MinGW client's platform behavior. Ctrl+C stops the Windows client.
The Windows executable and HTTP provider interoperability have been verified;
Unix-specific operations require verification on Unix.

## Protocol verification

```powershell
cargo test -p obfs-local
cargo clippy -p obfs-local --all-targets -- -D warnings
```

Tests use checked-in fixtures produced by the original C HTTP/TLS codecs,
compare fixed ClientHello and HTTP fields, and decode fragmented responses and
multiple TLS records. TCP tests cover both modes, half-close, readiness probes,
and timeout cleanup. Unlike the original C implementation, the Rust decoder
accepts headers split across reads and rejects oversized/truncated input safely.
Random values, log formatting, and invalid-input error text are not byte-identical.
Android VPN socket protection and macOS launchd socket activation are not included.

## License

GPL-3.0-or-later, following the simple-obfs source used for this port.
Original protocol code: copyright (C) 2013-2016 Max Lv. See [COPYING](COPYING).
This is a separate executable/package; the existing Shadowsocks crates do not
link to it.
