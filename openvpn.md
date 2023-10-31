# The OpenVPN protocol

## Status

This describes a subset of the protocol as implemented in OpenVPN 2.6.6. The
original motivation is to document for interoperability of MirageVPN, a newly
developed OpenVPN-compatible client with existing servers, reusing existing
configuration files. Initially, the client was developed with OpenVPN 2.4.7 in
mind. Not all features and configuration options of OpenVPN are covered in this
document, nor in the implementation itself.

The development of MirageVPN and this document was funded by
[Prototypefund](https://prototypefund.de) in 2019 - the German ministry for
research and education, and by NLnet in 2023 (via the December 2022 EU NGI
Assure call).

## Protocol overview

OpenVPN establishes a mutually authenticated tunnel between two endpoints. The
cryptographic properties depend on the concrete configuration. An OpenVPN tunnel
can be established via UDP or TCP. Two kinds of packets are distinguished:
control packets that are reliably transfered (acknowledged and retransmitted),
and data packets. Data packets are only accepted once a tunnel is established.

There are two modes of cryptographic operations that we support: static
cryptographic keys (in this document named "static"), where no handshake is
necessary and all key material is in the configuration (downside being no
forward secrecy), in contrast to ephemeral keys (in this document named "tls"),
which are negotiated during each handshake (and may be rekeyed - i.e. fresh key
material being negotiated). Another set of modes is the network topology:
peer-to-peer mode, where one peer connects with exactly one other peer; and a
traditional client-server mode, where multiple clients connect to a single
server.

In the "static" mode, only the peer-to-peer topology is supported - thus no
dynamic IP address configuration is needed.

## Implementation choices

We do not support all features of OpenVPN - while we strive to support more
features, some of the features we will never support:

### Compression

We do not support compression for sending data, since there are attacks - from
the OpenVPN manual page:
```
Compression and encryption is a tricky combination. If an attacker knows or is
able to control (parts of) the plain-text of packets that contain secrets, the
attacker might be able to extract the secret if compression is enabled. See e.g.
the CRIME and BREACH attacks on TLS and VORACLE on VPNs which also leverage to
break encryption. If you are not entirely sure that the above does not apply to
your traffic, you are advised to not enable compression.
```

For compatibility with existing configurations, we support LZO compression on
the receiving side.

### Ciphers

For the static mode, only AES-256-CBC is supported (configuration directive
`cipher`).

For the tls mode, only AEAD ciphers are supported, namely AES-128-GCM,
AES-256-GCM, and CHACHA20-POLY1305 (configuration directive `data-ciphers`).

## Static mode

In the static mode, there is no control channel. Every data packet is encrypted
and authenticated with the pre-shared keys (in the configuration file). To avoid
nonce reuse (for AEAD ciphers), only CBC ciphers are supported. There is no
support for client-server network topology. A warning is issued by MirageVPN
that there is a lack of forward security.

The advantage of the static mode is that it is easy to setup and there is not
even a TLS library required as dependency. Since the configuration is static,
there are not many things that may go wrong. It is easy to reason about, and
straightforward to think about.

The configuration must contain the directives `secret <file|inline>` and
`ifconfig <my-ip> <their-ip>`. The only supported `cipher` is `AES-256-CBC`.

Since the connection only contains the data channel, there is no header (i.e.
the packet wire format described below for TLS mode). Continue reading with the
"Data channel" section below.

## TLS mode

In TLS mode, first a TLS handshake is established - and the provided
certificates (server-only or mutually) are validated. The ephemeral
cryptographic keys are negotiated once the TLS session is established. The
connection (TCP or UDP) multiplexes both the control channel (carrying the TLS
handshake and ephemeral keying data) and the data channel. At any point, any
peer may decide to re-negotiate the cryptographic key material by utilizing the
control channel.

## Packet wire format

Each OpenVPN packet consists of a one-byte header, which high 5 bits encode the
operation ("op-code"), and low 3 bits encode the key identifier ("kid"). This is
followed by the actual payload, depending on the operation. If TCP is used as
transport, the header is prefixed by a two-byte length field.

The key identifier: the key identifier refers to an already negotiated TLS
session. OpenVPN seamlessly renegotiates the TLS session by using a new key
identifier for the new session. Overlap (controlled by user definable
parameters) between old and new TLS sessions is allowed, providing a seamless
transition during tunnel operation. The key identifier 0 is special and is only
and always used for the first session. Key identifiers 1-7 are used for
renegotiated sessions, and wraps around from 7 to 1 skipping 0.

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

The operation can be grouped into "data", "acknowledgement", and "control".

The data channel is always authenticated (either with a HMAC if the cipher is
CBC - where first encryption, and then the authentication is applied; or
directly with an AEAD cipher) and encrypted.

## Data channel

The data channel packet layout depends on the mode. If compression is used, the
first byte of the data specifies the algorithm (0xFA for the null compression).

### CBC

The packet consists of:
- the hmac over the IV and the encrypted packet (depends on the hmac algorithm),
- the IV for the packet (16 byte),
- and the encrypted packet.

The encrypted packet consists of:
- packet ID (4 byte),
- timestamp (only in static mode, 4 byte - seconds since UNIX epoch),
- and the data.

The encrypted packet is padded to be aligned to the cipher block size. The
padding consists in each byte the padding length, i.e. if the block size is 16,
and the data 13 bytes, the padding will be 3 bytes 0x03, 0x03, 0x03. If the data
is already aligned to the block size, an entire block will be appended.

### AEAD

The packet consists of:
- packet ID (4 byte),
- authentication tag (16 byte),
- and the data.

The nonce is 12 byte long, and consists of the packet_id prepended to the
implicit IV (from the ephemeral keys). As authentic data the packet id is used.

## Control channel

### Authentication and encryption of the control channel

The control channel can optionally be authenticated and encrypted:
- The `tls-auth` directive contains a pre-shared key for authentication of each
  control packet,
- the `tls-crypt` directive contains a pre-shared key for authentication and
  encryption of each control packet,
- the `tls-crypt-v2` directive contains a client-specific key for authentication
  and encryption of each control packet.

The authentication algorithm to use is specified by the `auth` directive, and
different hash algorithms from the SHA family are supported.

Authenticating the control channel mitigates denial-of-service (DoS) attacks,
since each incoming packet can quickly be checked whether it is originated by
a peer that knows the pre-shared key.

The `tls-crypt` mode additionally encrypts the control channel using a
pre-shared key (which is used by all clients). The `tls-crypt-v2` mode uses for
each client a distinct pre-shared key.

The advantage of encrypting the control channel is that certificates, exchanged
in the TLS handshake, are protected (TLS since 1.3 already encrypts
certificates), it makes it harder to identify OpenVPN traffic, and protects
against attackers who never know the pre-shared key (by quickly discarding
data).

The wire format of the control packets depend on the above configuration options
in place.

### Operations

The operations are:
- `SOFT_RESET` to initialize a rekeying. This is the first packet with a fresh
  key identifier
- `CONTROL` which carry a TLS payload
- `ACK` for acknowledgement packets
- `HARD_RESET_CLIENT` to initiate a new connection
- `HARD_RESET_SERVER` to answer to a `HARD_RESET_CLIENT`
- `DATA` carrying actual data

`HARD_RESET_{CLIENT,SERVER}` has 2 versions. Once the TLS session has been
initialized and authenticated, the TLS channel is used to exchange random key
material for bidirectional cipher and HMAC keys which will be used to secure
data channel packets. OpenVPN currently implements two key methods:
1) The first method directly derives keys using random bits obtained from the
   `random()` function.
2) The second method mixes random key material from both sides of the connection
  using TLS PRF mixing function.

The second method is preferred method and is the default for OpenVPN 2.0+. In
this document, **only** the second method will be mentioned.

All operations apart from DATA share a common header which describe a
_session ID_:
- local SID - 8 bytes: it's a random 64 bit value to identify TLS session. The
  TLS server side uses a HMAC of the client to create a pseudo random number for
  a SYN Cookie like approach.
- hmac - 20 bytes (depending on hash algo, commonly SHA1)
- packet id - 4 bytes
- timestamp - 4 bytes (seconds since Unix epoch). The specification says that
  this field is optional.
- acked packet-IDs array length - 1 byte
- acked packet-IDs - length * 4 bytes
- remote SID - 8 bytes (only if acked length > 0)
- TLS payload (only in control messages)

NOTE: For more details, the `protocol_dump` function in `src/openvpn/ssl.c`
specifies the packet format.

They consist of: local session ID, HMAC signature, packet ID, timestamp, acked
packet IDs, remote session ID (only present if acked packet IDs is non-empty),
message ID, TLS payload.

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

## Handshake protocol

Key establishment and configuration synchronization is achieved by a TLS
handshake over the control channel, over which configuration parameters are
exchanged. At any time after the tunnel is established, any party may use the
control channel for tunnel teardown or initiating a key exchange for rekeying
the tunnel. Multiple keys may be active at the same time, which is especially
useful for handing over from old keys to new keys without loosing in-flight
data.

## Configuration parameters and their interaction

For initializing a tunnel, first a remote must be selected from the
configuration. Depending on whether *remote-random* is configured, the list of
remotes will be randomized[^remote-random-bias] or not. A remote consists of a hostname or IP
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

`--resolv-retry` specifies the time spent to retry a DNS resolution in seconds.
The user is able to specify unlimited time and OpenVPN will retry indefinitely
or the user can disable the retry via `--resolv-retry=0`.

## TLS crypt v2

`tls-crypt-v2` adds encryption in addition to hmac authentication of the control channel.
Like with `tls-auth` the hmac authentication serves to protect the TLS stack from adversaries who do not have the authentication key.
The encryption layer in `tls-crypt-v2` (and `tls-crypt`) serves to keep the TLS handshake confidential so as to not reveal information from certificates to eavesdroppers.

In `tls-crypt`, which this spec will not cover much, the keys are shared between the server and all clients thus one client could eavesdrop on another client's TLS handshake with the server.
In `tls-crypt-v2` the server has a set of keys which are used when creating client keys.
A client key is a 'regular' OpenVPN static key along with the same client key wrapped using the server's keys.
In other words, the client has a key along with some data that is opaque to the client.
The opaque-to-the-client data is the client's key and some metadata encrypted and authenticated using the server's key.

On connection the client sends a message encrypted using its key and appends in plaintext the wrapped key.
The server can then unwrap (decrypt and authenticate) the client key and continue.

`P_CONTROL_HARD_RESET_CLIENT_V3` is added to have a smooth transition between
`--tls-auth`/`--tls-crypt` and `--tls-crypt-v2`.

The protocol works like that:

1) The server has a key `(Ke, Ka)`. The client has a key `Kc` and the the "wrapped" key `wKc`.
2) To the client it is opaque what `wKc` is and is sent to the server as-is.
   To the server `wKc` is wrapped with the key of the server `(Ke, Ka)` such as:
   `WKc = T || AES-256-CTR(Ke, IV, Kc || metadata) || len`
   where `T = HMAC-SHA256(Ka, len || Kc || metadata)`,
   `IV` is the 128 most significant bits of `T` (first 16 bytes of `T`) and
   `len` is the length of `wKc` as a 16 bit big endian integer which can be
   computed by adding the length of the client key, the length of the metadata,
   the hmac size and the size of the length field itself (two bytes).
3) The client sends (->) `P_CONTROL_HARD_RESET_CLIENT_V3` wrapped with `Kc`
   plus `WKc` (which is **not** wrapped)
4) The server receives (<-) the message:
  - reads the `WKc` length field from the end of the message
  - extract `WKc` from the message
  - unwraps `WKc` (with `Ke`) in order to obtain `Kc`
  - uses `Kc` to verify `P_CONTROL_HARD_RESET_CLIENT_V3`
5) if something fails, the server **doesn't** tell the client about that (DoS protection)
6) server can check metadata (see `--tls-crypt-v2-verify`), we verify them only
   **after** the TLS handshake
7) Client and server use `Kc` for any data through the control channel

### Metadata
The metadata in `wKc` comes in two types tagged with a single byte:
- `USER`/`0x00` - user-defined data, and
- `TIMESTAMP`/`0x01` - 64-bit unix timestamp
The length of the metadata when unwrapping can be deduced by `len` and the
fixed sizes of `T` and `Kc`.

As examples of `tls-crypt-v2-verify` scripts they suggest to reject keys older
than N days, or for `USER` metadata to embed the certificate serial and check
it up against a CRL.

## OpenVPN static keys

OpenVPN has a concept of static keys which is 2048 bits, or in some cases 1024 bits, of random data.
A 2048 bit (256 byte) key is a pair of two directional keys, each of 1024 bits (128 bytes).
Each directional key is yet another pair (`Ke, Ka)` of 512 bits (64 bytes) each.
`Ke` is the key used for the symmetrical cipher, and `Ka` is used for the hmac if not using an AEAD cipher.
The first *N* bytes of `Ke` are used as the key for the cipher where *N* is the key size of the cipher.
As well for `Ka` only the first *M* bytes are used as key for the hmac where *M* depends on the hash.
For SHA1 the key size is 20 bytes, for example.

### Endianness
The OpenVPN documentation sometimes says to use the *K* most significant bits as key.
This is slightly confusing as they never mention the endianness.
Apparently they mean big endian, so in other words you use the first *K*/8 bytes as key.

### Direction

OpenVPN operates with a sense of direction for the keys.
This means that one key pair is used for encrypting and authenticating remote packets and the other is used for the local packets.
**TODO:** figure out what direction 0 and 1 means for the key pairs.

### File format

The file format used to store OpenVPN static keys looks on the surface as if they are PEM-encoded starting with `-----BEGIN OpenVPN Static key V1-----` and ending with `-----END OpenVPN Static key V1-----` but unlike PEM the body is a hexadecimal encoding (instead of base64 encoding) of the keys concatenated.
Anything before the header and after the footer is ignored.

[^remote-random-bias]: Note that OpenVPN uses a *biased* shuffling algorithm,
  i.e. some remotes permutations are more likely than others.
  See [`init_connection_list()` in
  src/openvpn/init.c](https://github.com/OpenVPN/openvpn/blob/0793eb105c5720c4eb31af71c9db81459439e510/src/openvpn/init.c#L474-L498)
  for the implementation, and the following article for a description of the
  bias: http://datagenetics.com/blog/november42014/index.html. The usage of
  `get_random() % N` is also biased (although negible for small `N`)
