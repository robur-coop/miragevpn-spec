# The OpenVPN protocol

## Status

This describes a subset of the protocol as implemented in OpenVPN 2.4.7. The
original motivation is to document for interoperability of a newly developed
OpenVPN client with existing servers, reusing existing configuration files.  The
scope for key exchanges is TLS (i.e. key-method 2), the pre-shared secret mode
is not described in this document. Not all features and configuration options of
OpenVPN are covered in this document, nor in the implementation itself.

This document has been updated according to OpenVPN v2.6~rc2.

## Terminology

## Protocol overview

OpenVPN establishes a mutually authenticated tunnel between two endpoints. The
cryptographic properties depend on the concrete configuration. An OpenVPN tunnel
can be established via UDP or TCP. Two kinds of packets are distinguished:
control packets that are reliably transfered (acknowledged and retransmitted),
and data packets. Data packets are only accepted once a tunnel is established.

## Packet wire format

Each OpenVPN packet consists of a one-byte header, which high 5 bits encode the
operation, and low 3 bits encode the key identifier. This is followed by the
actual payload, depending on the operation. The header is prefixed by a two-byte
length field if TCP is used as transport.

The key identifier: the `key_id` refers to an already negotiated TLS session.
OpenVPN seamlessly rengotiates the TLS session by using a new `key_id` for the
new session. Overlap (controlled by user definable parameters) between old and
new TLS sessions is allowed, providing a seamless transition during tunnel
operation.

```
  1 byte header
 .-------------.
+-+-+-+-+-+-+-+-+
| | | | | | | | |
+-+-+-+-+-+-+-+-+

| op-code | kid |

op-code: the operation
kid: the key identifier
```

The operations are:
- SOFT_RESET to initialize a rekeying. This is the first packet with a fresh
  key identifier
- CONTROL which carry a TLS payload
- ACK for acknowledgement packets
- HARD_RESET_CLIENT to initiate a new connection
- HARD_RESET_SERVER to answer to a HARD_RESET_CLIENT
- DATA carrying actual data

HARD_RESET_{CLIENT,SERVER} has 2 versions. Once the TLS session has been
initialized and authenticated, the TLS channel is used to exchange random key
material for bidirectional cipher and HMAC keys which will be used to secure
data channel packets. OpenVPN currently implements two key methods:
1) The first method directly derives keys using random bits obtained from the
   `random()` function.
2) The second method mixes random key material from both sides of the connection
  using TLS PRF mixing function.

The second method is preferred method and is the default for OpenVPN 2.0+. In
this document, **only** the second method will be mentioned.

```
+-+
| | = 1 byte
+-+

+-+-+-+-+-+-+-+-+-   -+-+-+-+-+-+-+-+-+-+-   -+-+-+-+-+-+-+-+-+-
| | | | | | | | | ... | | | | | | | | | | ... | | | | | | | | | ...
+-+-+-+-+-+-+-+-+-   -+-+-+-+-+-+-+-+-+-+-   -+-+-+-+-+-+-+-+-+-
|               |     |       |       | |     |               |
|SID            |HMAC |PKT-ID |TIME   |L|ARR  |Remote SID     |TLS Payload

SID: local session ID
HMAC: 20 bytes if SHA1 is used
PKT-ID: packet ID
TIME: timestamp
L: length of the packet IDs array
ARR: 4 bytes * L
Remote SID: remote session ID
TLS Payload: only for CONTROL message
```

All operations apart from DATA share a common header which describe a
_session ID_:
- local SID - 8 byte: it's a random 64 bit value to identify TLS session. The
  TLS server side uses a HMAC of the client to create a pseudo random number for
  a SYN Cookie like approach.
- hmac - 20 bytes (depending on hash algo, commonly SHA1)
- packet id - 4 byte
- timestamp - 4 byte (seconds since Unix epoch). The specification says that
  this field is optional.
- acked packet-IDs array length - 1 byte
- acked packet-IDs - length * 4 byte
- remote SID - 8 byte (only if acked length > 0)
- TLS payload (only in control messages)

NOTE: For more details, the `protocol_dump` function specifies the packet
format.

They consist of: local session ID, HMAC signature, packet ID, timestamp, acked
packet IDs, remote session ID (only present if acked packet IDs is non-empty),
message ID, TLS payload.

The DATA packet is described as is:
```
+-   -+-   -+-
| ... | ... | ...
+-   -+-   -+-
|HMAC |IV   |DATA

HMAC: 20 bytes if SHA1 is used
IV: "block-size" byte(s)
DATA: padded to "block-size" byte(s)
```

- hmac - 20 bytes
- IV - cipher block-size
- data - padded to block-size

A DATA packet consists of a HMAC signature, its ciphertext IV, and the actual
ciphertext.

## Handshake protocol

Key establishment and configuration synchronization is achieved by a TLS
handshake over the control channel, over which configuration parameters are
exchanged. At any time after the tunnel is established, any party may use the
control channel for tunnel teardown or initiating a key exchange for rekeying
the tunnel. Multiple keys may be active at the same time, which is especially
useful for handing over from old keys to new keys without loosing in-flight
data.

## Encryption / decryption and padding

The purpose of padding is to align data to the cipher block size. The padding
consists in each byte the padding length, i.e. if the block size is 16, and the
data 13 bytes, the padding will be 3 bytes 0x03, 0x03, 0x03.  If the data is
already aligned to the block size, an entire block will be
appended.

## Configuration parameters and their interaction

For initializing a tunnel, first a remote must be selected from the
configuration. Depending on whether *remote-random* is configured, the list of
remotes will be randomized or not. A remote consists of a hostname or IP
address, an optional port (default to 1194) and optional protocol
(TCP/UDP/TCPv4/UDPv4/TCPv6/UDPv6), defaults to *proto*, filtered depending on
*force-proto*. If a hostname is configured, this is resolved using DNS, and one
of the returned IP addresses is used. If *connect-timeout* is reached without an
initial packet exchange in both directions, the next remote is tried. If
*hand-window* is exceeded without completing the handshake, the next remote is
chosen. If the list of remotes is all tried, the client waits for at least
*connect-retry* seconds (with a backoff factor of 2 after 5 retries, limited to
the optional max argument, default to 300). If *connect-retry-max* is reached
(defaults to unlimited) without establishing a connection, the client exits.

TODO: resolv-retry
