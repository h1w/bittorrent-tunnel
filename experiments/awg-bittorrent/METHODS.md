# Camouflage methods under test

Each method carries AWG datagrams (handshake and junk included) inside a
different BitTorrent-ecosystem wire shape. The same AWG profile is used
everywhere: `S1..S4=32`, `H1..H4=101..104`, `Jc=4`, `Jmin=40`, `Jmax=100`.
The custom Bind has no plaintext AWG UDP path in carrier mode.

## Reference: `request/piece` (BEP 3 peer protocol)

Outer wire shape: 68-byte `BitTorrent protocol` handshake, `bitfield` (id 5),
`interested` (id 2), `unchoke` (id 1), `request` (id 6), and `piece` (id 7)
whose body is a uint16 length-prefixed AWG datagram plus random padding filling
a 2048-byte block.

Six transport configurations of this one method:

| Variant | Outer transport |
|---|---|
| `awg-bt-tcp` | kernel TCP, TCP_NODELAY |
| `awg-bt-libutp` | reference C++ libutp |
| `awg-bt-go-default` | pure-Go µTP, stock send policy |
| `awg-bt-go-nn` | pure-Go µTP, Nagle hold bypassed |
| `awg-bt-go-nn-dup` | no-Nagle with duplicated outer UDP packets |
| `awg-bt-go-nn-2lanes` | no-Nagle across two connections, round-robin |

`awg-direct` (bare AWG over UDP through the same delay emulator) is the
baseline, not a request/piece configuration.

## Method: `extended` (BEP 10)

Outer wire shape: 68-byte `BitTorrent protocol` handshake, then a BEP 10
extension handshake (message id 20, extended id 0, bencoded `d1:md5:btawgi1ee`),
then data messages (message id 20, private extended id 1) whose body is a uint16
length-prefixed AWG datagram plus random padding to a 2048-byte block.
Symmetric on one connection.

Configurations: `awg-bt-ext-utp` (pure-Go µTP, Nagle bypassed), `awg-bt-ext-tcp`
(kernel TCP).

## Method: `webseed` (BEP 19)

Outer wire shape: `HTTP/1.1 GET` with a `Range` header, `206 Partial Content`
response whose body is a stream of records, each a uint16 length-prefixed AWG
datagram plus random padding to a 2048-byte block. Each side hosts a minimal
webseed endpoint and requests ranges from the other, giving a bidirectional
flow over two TCP connections. No BitTorrent handshake.

Configuration: `awg-bt-webseed` (kernel TCP).

## Benchmark channel

Every variant, including the TCP-only ones, is measured on `clean40`: 20 ms
one-way delay applied to every outer packet in each direction (UDP via the
delay-emulator queue, TCP via a write-side `wrapDelay` on each connection).
The bare-AWG baseline runs through the same emulator, so the delta column is
the added latency of camouflage alone.
