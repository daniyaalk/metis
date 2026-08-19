# metis

eBPF TCP observability agent. Captures outbound TCP traffic, measures MySQL query latency, and ships metrics to Telegraf using InfluxDB line protocol over UDP.

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

```shell
cargo build --release
sudo ./target/release/metis --config metis.toml
```

Cargo build scripts automatically compile the eBPF programs and embed them in the binary. Root (or `CAP_BPF` + `CAP_NET_ADMIN`) is required to load eBPF programs.

## Configuration

Metis is configured via a TOML file. Pass the path with `--config` (defaults to `metis.toml` in the working directory). If the file is not found, all settings fall back to their defaults.

```toml
# Percentage of tcp_sendmsg connections to capture (0.0–100.0).
# Sampled once per connection, on its first packet, and reused for every later
# packet on that connection — so a sampled-in connection never loses e.g. a
# MySQL handshake packet while its query packets are captured.
# Applies to all modules that use the tcp_sendmsg probe (mysql, http).
# Supports fractional values: 0.01 = 1 in 10 000 connections.
tcp_sendmsg_sample_rate = 100.0

[telegraf]
# UDP address of the Telegraf StatsD/line-protocol listener.
address = "127.0.0.1:8125"

[modules.tcp]
enabled = true
# ports = [80, 443]   # omit to capture all ports

[modules.mysql]
enabled = true
ports = [3306]

[modules.http]
enabled = false
ports = [80, 8080]
```

### Module defaults

| Module | enabled | ports         |
|--------|---------|---------------|
| tcp    | true    | all ports     |
| mysql  | true    | 3306          |
| http   | false   | 80            |

### Metrics emitted

All metrics are sent to Telegraf using InfluxDB line protocol over UDP. Configure the [`inputs.socket_listener`](https://github.com/influxdata/telegraf/tree/master/plugins/input/socket_listener) plugin in Telegraf with `service_address = "udp://:8125"`.

| Measurement                | Tags                        | Fields          | Module |
|----------------------------|-----------------------------|-----------------|--------|
| `bpf_tcp_probe`            | src/dest ip, port, pid      | cwnd, rtt, …    | tcp    |
| `bpf_tcp_retransmit_skb`   | src/dest ip, port, pid      | —               | tcp    |
| `bpf_tcp_send_reset`       | src/dest ip, port, pid      | —               | tcp    |
| `bpf_tcp_receive_reset`    | src/dest ip, port, pid      | —               | tcp    |
| `mysql_query_latency`      | port, query (normalized)    | latency_ms      | mysql  |

MySQL queries are normalized before use as tag values: string literals and numeric literals are replaced with `?` to prevent cardinality explosion.

## Cross-compiling on macOS

Cross compilation works on both Intel and Apple Silicon Macs.

```shell
cargo build --package metis --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"rust-lld\"
```

Copy `target/${ARCH}-unknown-linux-musl/release/metis` to the target Linux host and run it there.

## License

With the exception of eBPF code, metis is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
