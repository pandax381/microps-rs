# microps-rs

A small educational TCP/IP protocol stack written in Rust, reimplemented from [microps].

This is a Rust port of [microps][microps], the C-language TCP/IP stack from the book
*ゼロからのTCP/IPプロトコルスタック自作入門* (山本雅也 著, マイナビ出版, 2025).

[microps]: https://github.com/pandax381/microps

## Features

- **Link layer**: Ethernet (Linux TAP), Loopback
- **Internet layer**: ARP with cache, IPv4 with routing, ICMP (echo reply, destination unreachable)
- **Transport layer**: UDP, TCP (RFC 793 — connection management, retransmission, half-close, simultaneous open/close)
- **Socket API**: BSD-style `socket` / `bind` / `listen` / `accept` / `connect` / `send` / `recv` / `sendto` / `recvfrom` / `close`

The implementation follows the book's 30 steps, one commit per step.

## Layout

- `src/` — the `microps` library crate (the protocol stack)
- `test/` — a test binary that exercises the stack
- `xtask/` — `cargo xtask` helpers for managing the TAP device

## Setup

Create the TAP device once per boot:

```sh
cargo xtask tap create
```

This brings up `tap0` at `192.0.2.1/24`. The stack itself answers on
`192.0.2.2`. Tear it down with:

```sh
cargo xtask tap delete
```

## Run

```sh
cargo run --bin test
```

The test binary listens on TCP port 7 as an echo server. From another
shell:

```sh
nc -v 192.0.2.2 7
```

Type a line and it bounces back. `Ctrl+C` on the `nc` side closes the
connection; the server accepts the next one. `Ctrl+C` on the server
side shuts the stack down.

## License

[MIT](LICENSE).
