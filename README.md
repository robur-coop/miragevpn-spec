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
research and education, and by [NLnet](https://nlnet.nl) in 2023/2024 (via the
December 2022 EU [NGI Assure](https://www.assure.ngi.eu/) call). Learn more at
the [NLnet project page](https://nlnet.nl/project/MirageVPN).

In the meantime, there is a [OpenVPN-RFC](https://github.com/openvpn/openvpn-rfc)
effort which provides protocol documentation.

This is a live document which we will extend whenever we add new protocol
features to MirageVPN or we discover corner cases in the protocol.

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

We do not support all features of OpenVPN currently. While we strive to support
more features, there are features we don't plan to support:

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

### Terminology

#### OpenVPN replay packet id - MirageVPN replay id

OpenVPN defines a "replay_packet_id", which is a uint32 value, usually combined
with another uint32 value, the timestamp. The purpose of this is that an
attacker is not able to replay a packet to the client or server. The invariant
is that the replay packet id must increase for each packet being sent. We use
the term "replay ID" for the uint32 counter, and always treat the timestamp
separately.

#### OpenVPN packet id - MirageVPN sequence number

OpenVPN defines the term "packet id" as a uint32 value which is part of every
control packet (apart from acknowledgements). The purpose is to have a strict
gap-free sequence of control packets (especially when using UDP and
retransmissions are necessary).

We use (due to confusion with "replay packet id") the term sequence number for
this monotonically increasing number that is attached to control packets.

## Transport

If TCP is used as transport, the header is prefixed by a two-byte length field.
Below, we focus on UDP, where no header length is prefixed.

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

There is no control channel in static mode, only the data channel. This means
there is also no one-byte header described below for the TLS mode.

## TLS mode

In TLS mode, first a TLS handshake is established - and the provided
certificates (server-only or mutually) are validated. The ephemeral
cryptographic keys are negotiated once the TLS session is established. The
connection (TCP or UDP) multiplexes both the control channel (carrying the TLS
handshake and ephemeral keying data) and the data channel. At any point, any
peer may decide to re-negotiate the cryptographic key material by utilizing the
control channel.

### Packet wire format

Each OpenVPN packet in TLS mode consists of a one-byte header, which high 5 bits
encode the operation ("op-code"), and low 3 bits encode the key identifier
("kid"). This is followed by the actual payload, depending on the operation.

The key identifier: the key identifier refers to an already negotiated TLS
session. OpenVPN seamlessly renegotiates the TLS session by using a new key
identifier for the new session. Overlap (controlled by user definable
parameters) between old and new TLS sessions is allowed, providing a seamless
transition during tunnel operation. The key identifier 0 is special and is only
and always used for the first session. Key identifiers 1-7 are used for
renegotiated sessions, and wraps around from 7 to 1 skipping 0.

```
+-+
| | - 1 bit
+-+

  1 byte header
 .-------------.
+-+-+-+-+-+-+-+-+
| | | | | | | | |
+-+-+-+-+-+-+-+-+
| op-code | kid |

op-code: the operation
kid: the key identifier
```

The operation are be grouped into "data", "acknowledgement", and "control".

## Data channel

The data channel packet layout depends on the mode. If compression is used, the
first byte of the data specifies the algorithm (0xFA for the null compression).

The data channel is always authenticated (either with a HMAC if the cipher is
CBC; or with an AEAD cipher) and encrypted.

### CBC

The packet consists of:
- the hmac over IV and encrypted packet (configured by the `auth` directive),
- the IV for the packet (16 byte),
- and the encrypted packet.

The encrypted packet consists of:
- replay ID (4 byte)
- timestamp (only in static mode, 4 byte - seconds since UNIX epoch),
- and the data.

The encrypted packet is padded to be aligned to the cipher block size. The
padding consists in each byte the padding length, i.e. if the block size is 16,
and the data 13 bytes, the padding will be 3 bytes 0x03, 0x03, 0x03. If the data
is already aligned to the block size, an entire block will be appended.

### AEAD

The packet consists of:
- replay ID (4 byte)
- authentication tag (16 byte),
- and the encrypted data.

The nonce is 12 byte long, and consists of the replay id prepended to the
implicit IV (from the ephemeral keys). As associated data the replay id is used.

## Control channel

The purpose of the control channel is to negotiate ephemeral keys, authenticate,
and negotiation of other settings (timeouts, rekeying intervals, IP addresses,
..) of the tunnel. The control channel can be *further* authenticated and
encrypted using several mechanisms described below. Initially, a TLS connection
is established over the control channel, and then parameters are negotiated.
The client authentication can be via X.509 client certificates (as part of the
TLS handshake) or username and password (once the TLS session is established).
The server is always authenticated via an X.509 server certificate.

### Authentication and encryption of the control channel

The purpose of authentication of the control channel is reduction of the attack
surface of the server and reduction of the load (avoiding denial of service
attacks) on the server -- i.e. no code of the (potentially vulnerable) TLS
library is executed if the control packet is not properly authenticated.

The advantage of encrypting the control channel is that certificates, exchanged
in the TLS handshake, are protected (TLS since 1.3 already encrypts
certificates), it makes it harder to identify OpenVPN traffic, and protects
against attackers who never know the pre-shared key (by quickly discarding
data).

The different specified mechanisms are:
- The `tls-auth` directive contains a pre-shared key for authentication of each
  control packet,
- the `tls-crypt` directive contains a pre-shared key for authentication and
  encryption of each control packet,
- the `tls-crypt-v2` directive contains a client-specific key for authentication
  and encryption of each control packet.

The authentication algorithm to use is specified by the `auth` directive, which
supports hash algorithms of the SHA family.

The `tls-crypt` mode additionally encrypts the control channel using a
pre-shared key (which is shared amongst all clients). The `tls-crypt-v2` mode
uses for each client a distinct pre-shared key. For both `tls-crypt` and
`tls-crypt-v2` the cipher and hmac algorithm is fixed to AES-256-CBC and SHA256
HMAC respectively.

The wire format of the control packets depend on the above configuration options
in place.

### Plain header

The plain header is shown below:
```
+-+
| | - 1 byte
+-+


 h .---own SID---. n ack .-peer SID?-. .-seq-.
+-+-+-+-+-+-+-+-+-+-+...+-+-+-+-+-+-+-+-+-+-+-+
| | | | | | | | | | |...| | | | | | | | | | | |
+-+-+-+-+-+-+-+-+-+-+...+-+-+-+-+-+-+-+-+-+-+-+

h - one byte header (described above)
own SID - own session ID
n - number of ACKed sequence numbers
ack - list of ACKed sequence numbers (length is n * 4 bytes)
peer SID? - peer session ID (only if n > 0)
seq - sequence number
```

The session IDs are opaque (random 64 bit) values for identifying the TLS
session. Each peer uses a separate counter for the sequence numbers starting at
0. The control packets must be sequential, with the gap-free sequence number
monotonically increasing.

### TLS auth header

The TLS auth header contains a hmac and a replay id (also known as replay
packet id in OpenVPN, consisting of a 4 byte id and a 4 byte timestamp), which
are put just after the own session ID. The size of the hmac depends on the hmac
algorithm being used - configured by the `auth` directive. The hmac key is the
same length as the hmac output, it is pre-shared between all clients and the
server.

```
 h .---own SID---. hmac .-rID-. .-time. n ack .-peer SID?-. .-seq-.
+-+-+-+-+-+-+-+-+-+....+-+-+-+-+-+-+-+-+-+...+-+-+-+-+-+-+-+-+-+-+-+
| | | | | | | | | |....| | | | | | | | | |...| | | | | | | | | | | |
+-+-+-+-+-+-+-+-+-+....+-+-+-+-+-+-+-+-+-+...+-+-+-+-+-+-+-+-+-+-+-+
```

The replay ID is used to prevent replay attacks (where someone sends a
captured packet back a second time), and must be incremented for each packet
sent.

The hmac is computed over the pseudo-header consisting of:
- rID - the replay ID (a 4 byte ID)
- time (4 byte timestamp in seconds since UNIX epoch)
- one-byte header
- own session ID
- n - the number of ACKed sequence numbers
- list of acked sequence numbers
- peer session ID (if n > 0)
- sequence number

When the hmac does not match, an implementation must discard the packet.


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

## Handshake protocol

Key establishment and configuration synchronization is achieved by a TLS
handshake over the control channel, over which configuration parameters are
exchanged. At any time after the tunnel is established, any party may use the
control channel for tunnel teardown or initiating a key exchange for rekeying
the tunnel. Multiple keys may be active at the same time, which is especially
useful for handing over from old keys to new keys without loosing in-flight
data.

### Data channel key exchange

After the TLS session is established the client sends a key exchange message and the server responds with another key exchange message over the TLS-encrypted control channel.
There are two current mechanisms to actually derive keys: TLS PRF-based (being deprecated) and TLS-EKM.
In both cases the same key exchange message is used:

<!-- TODO: we should be more consistent in how we diagram this -->
```
string := {
  length - 2 bytes;
  characters - length bytes (including terminating NUL byte);
}

key_exchange := {
  zeroes - 4 bytes;
  key method - 1 byte;
  pre master (only sent by client) - 48 bytes;
  random1 - 32 bytes;
  random2 - 32 bytes;
  opt - string;
  user - string;
  password - string;
  peerinfo - string;
}
```

The message starts with a fixed 4 NUL bytes.
The key method is 2.

`pre_master` is 48 random bytes and is only sent by the client; the server omits this field.
`random1` and `random2` are 32 random bytes each.
The remainder are strings encoded using a 2 byte length field followed by a NUL-terminated byte sequence.
The length is a 16 bit big endian integer.
The empty string can be encoded as a 0 length byte sequence - which then is not NUL-terminated - or a 1 length byte sequence consisting of the NUL byte.
`opt` is a string of options and is falling out of favor.
The `user` and `password` strings are used for user & pass phrase authentication.
The length of those fields are 0 if password authentication is not used or in the server's key exchange message.
Finally, peerinfo is a string of key=value bindings separated by line feed (`\n`).
Only the client sends peerinfo; the server will use a value of length 0.

#### Peerinfo
The peerinfo mechanism is used to communicate to the server some information about the client.
Some important options are:

- `IV_PROTO` is important and is a decimal integer which is to be interpreted as a bit field.
  The most relevant bits in the bit field are:
  * bit 0: Reserved and should be 0.
  * bit 2: Request push. The client can set this bit to inform the server that it can send the [`PUSH_REPLY`](#push-request) without waiting for the client to send a `PUSH_REQUEST` message.
  * bit 3: The client supports TLS key material exporters (TLS-EKM). This is used to negotiate the key derivation mechanism used in [data channel cipher negotiation](#data-channel-cipher-negotation).
  * bit 7: The client can send the control channel [`EXIT`](#control-channel-exit) message. This also means the client will support the [`protocol-flags`](#protocol-flags) config option in a push reply. Notably, the `protocol-flags` push reply option will be used to signal tls-ekm support instead of `key-derivation` push reply option.
- `IV_CIPHERS` is as well important and used for [data channel cipher negotiation](#data-channel-cipher-negotation). The client lists what ciphers it supports. The server then one of the ciphers and informs the client in a [`PUSH_REPLY`](#push-request) or aborts the connection if no suitable cipher was found.

### Data channel cipher negotiation

There are two parts of data channel cipher negotiation: negotiating the way to derive the key material, and negotiating the cipher to use.

#### Negotiating key material

There are two current mechanisms to derive key material:
- the old way using TLS 1.0 pseudo-random function (TLS-PRF)
- the new way using TLS key material exporters (TLS-EKM)

#### PRF

The TLS-PRF uses the pseudo-random function defined by the TLS 1.0 RFC (RFC 2246) with the `pre_master` (selected by the client) as secret, and random data (concatenation of `random1` from both server and client) as seed. This results in the `master_key` (48 bytes).

The actual key material is then computed using the same pseudo-random function with the just computed `master_key` as secret, as seed the concatenation of both `random2` from server and client, together with the session ids.

This is the default unless TLS-EKM is negotiated.

#### EKM

The new way uses the key material exporters mechanism of TLS, as defined in  RFC 5705 (for TLS 1.0 - 1.2, TLS 1.3 has a different computation).

The client signals support for TLS EKM by setting bit 3 in [`IV_PROTO`](#peerinfo).
The server, if the client supports TLS EKM, replies with a [`PUSH_REPLY`](#push-request) with `key-derivation tls-ekm` or `protocol-flags` with `tls-ekm`.
The label `EXPORTER-OpenVPN-datakeys` is used to derive the keys.

#### Negotiating cipher

The client signals supported ciphers by sending the [peerinfo](#peerinfo) key `IV_CIPHERS` with a colon-separated (`:`) list of ciphers.
The client may as well send the peerinfo key-value`IV_NCP=2` which means the client supports both AES 128 GCM and AES 256 GCM.
`IV_NCP=2` is deprecated in favor of `IV_CIPHERS`.
`IV_NCP=2` can be set in addition to `IV_CIPHERS` for compatibility with older implementations.

The server decides a cipher from the intersection of the client's ciphers and the servers `--data-ciphers`.
The server SHOULD choose the first cipher in its `--data-ciphers` list that the client supports.
If there are no ciphers in commen the server sends a [`AUTH_FAILED`](#auth_failed) control channel message.
Otherwise, the server sends to the client the chosen cipher in a [`PUSH_REPLY`](#push-request) control channel message using the `cipher` option.

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

The key direction 0 means that the first half of the key block is used for sending, and the second half is used fo receiving. The key direction 1 means the opposite. If no key direction is specified, both sending and receiving use the first half of the key block.

In a setup, either there should be no key direction specified, or one side has 1, the other 0. Otherwise communication won't succeed.

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
