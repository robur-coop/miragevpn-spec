# The OpenVPN protocol

## Status

This describes a subset of the protocol as implemented in OpenVPN 2.4.7. The
original motivation is to document for interoperability of a newly developed
OpenVPN client with existing servers, reusing existing configuration files.  The
scope for key exchanges is TLS (i.e. key-method 2), the pre-shared secret mode
is not described in this document. Not all features and configuration options of
OpenVPN are covered in this document, nor in the implementation itself.

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

The operations are:
- SOFT_RESET to initialize a rekeying. This is the first packet with a fresh
  key identifier
- CONTROL which carry a TLS payload
- ACK for acknowledgement packets
- HARD_RESET_CLIENT to initiate a new connection
- HARD_RESET_SERVER to answer to a HARD_RESET_CLIENT
- DATA carrying actual data

All operations apart from DATA share a common header:
- local SID - 8 byte
- hmac - 20 bytes (depending on hash algo, commonly SHA1)
- packed id - 4 byte
- timestamp - 4 byte (seconds since Unix epoch)
- acked length - 1 byte
- acked IDs - length * 4 byte
- remote SID - 8 byte (only if acked length > 0)
- TLS payload (only in control messages)

They consist of: local session ID, HMAC signature, packet ID, timestamp, acked
packet IDs, remote session ID (only present if acked packet IDs is non-empty),
message ID, TLS payload.

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
mechanism is to contain the padding length in each byte, i.e. if the block size
is 16, and the data 13 bytes, the padding will be 3 bytes containing 0x03 each.
If the data is already aligned to the block size, an entire block will be
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
