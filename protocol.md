Note: this document was written in vim, github butchers the formatting. I highly recommend you read the raw text version.

# SPDB
## SPeeDyBase

SPDB is a simple network, designed to be very fast(implied by the name) and highly adaptable to many use-cases. It supports exchanging hash-addressed immutable blocks of data, as well as creating signed and encrypted uni-directional data channels and providing weak anonymity guarantees.

The primary use-case of SPDB is as a server-side utility similar to IPFS gateways, but flexible enough to meet many different needs.

## Design Goals

The design goals of SPDB are pretty simple:
SPDB should be
- fast: implied by the name. The primary goal of speedybase is to be significantly faster than other unstructured distributed networks at scale. Particularly, the protocol should usually find an almost-optimal path in a reasonable time, without any knowledge of the network structure.
- scalable: the network should be no more congested with a billion nodes than a thousand
- reliable: it should be uncommon for an endpoint lookup to fail if the endpoint is not far away in the network
- low-resources: I should be able to run speedybase on a toaster
- network- and operating system-agnostic: there should be as few assumptions as possible on the underlying network protocols.
- resilient to DOS attacks

The main routing model is similar to ant routing. Nodes must exchange keys and contact information out-of-band to participate in the network. There are a few reasons for this:
1) SPDB is intended to protect the users' privacy. By exchanging keys out-of-band and having no handshake protocols it is made difficult to detect when SPDB is being used.
2) By not enforcing any particular method of exchanging contact information, SPDB can be used in a variety of contexts. File-sharing networks may desire to use a DHT, website administrators may desire to have 'coordinator' nodes, friends may just want to connect to their friends.
3) DOS and Sibyl attacks are mitigated by never accepting packets from 'un-vetted' peers
4) Issues of trust between nodes are turned into issues of trust between operators, which may be very different in different contexts
5) Public-key cryptography is computationally expensive and vulnerable to quantum computers. It is used by SPDB only when no alternative exists.

Currently, SHA256 is the only hashing function used(aside from Poly1305 for AEAD). This may change in the future if weaknesses are found.

## Endpoints
"endpoint" refers to a resource which can be requested, it can be static or dynamic or a mix of both.
The protocol has two specific types of endpoint which are handled in-protocol, but extensions could easily be made to include more types of endpoint

## Routing

SPDB uses an ant routing protocol. Fetching the contents of an endpoint starts with a SEEK packet, which is forwarded randomly through the network until it either expires or comes to a node which has participated in routing the requested endpoint recently enough to remember it.
The origin then chooses a route based on the speed with which it gets a HAVE packet back. 3-4 SEEKs should be sent simultaneously for this to be effective.
In some network topologies, it may be advantageous to have a distinguished "upstream" neighbor to whom all SEEKs are forwarded. In this case SPDB becomes much more like traditional IP routing, but with some advantages.

## Message Format Description

The protocol is designed to run on top of a base networking layer which supports sending packets with an MTU of 1272 bytes asynchronously. Incomplete or currupted packets are ignored.
All integers are in big-endian and are unsigned unless specified otherwise.
All packets are padded with random data to be 1272 bytes long.
All packets have the following format:

```
+----------------------------------------+
| nonce: 16 bytes                        |
+----------------------------------------+
| nonce for reply: 16 bytes              |
+----------------------------------------+
| packet type: 1 byte                    |
+----------------------------------------+
| flags: 1 byte                          |
+----------------------------------------+
| payload length: 2 bytes                |
+----------------------------------------+
| payload                                |
+----------------------------------------+
| padding                                |
+----------------------------------------+
| AEAD tag: 16 bytes                     |
+----------------------------------------+
```

Everything between the nonce and AEAD tag is encrypted with the appropriate nonce and key and verified with the AEAD tag. Messages which fail verification are ignored
Nonces are sent along with every packet even when not technically necessary, as they serve to identify responses.
When a message is forwarded, it should always have its nonce and reply nonce changed, so that each message in a forwarding chain has a different nonce

## Message Flags
Flags send extra info about how the packet should be routed/handled. Currently they do nothing.

non-standard flags should have masks of 0x10 or higher.

## EndpointID's
EndpointID's are calculated using hashes of the data at the endpoint. They are 36 bytes long, with the following format:

```
+----------+------------------+--------------------------+---------------------------------+
| bit      | 0-1              | 2-31                     | 32-287                          |
+----------+------------------+--------------------------+---------------------------------+
| contents | endpoint type    | size of non-dynamic data | triple hash of non-dynamic data |
+----------+------------------+--------------------------+---------------------------------+
```

The triple-hash is computed by SHA256('notanaughtyboy' ++ SHA256(SHA256(data)))

Endpoint type can have the following values:

```
+----+-----------------------------------------------------------------+
| 00 | no dynamic data                                                 |
+----+-----------------------------------------------------------------+
| 01 | dynamic data consists of linked EndpointIDs that the server has |
+----+-----------------------------------------------------------------+
| 10 | hashed data is a public key, dynamic data is encrypted          |
+----+-----------------------------------------------------------------+
| 11 | protocol extension                                              |
+----+-----------------------------------------------------------------+
```

EndpointID's provide a weak form of identity. Primarily, they are used for the following two use-cases: exchanging immutable blocks of hash-addressed data, and exchanging public keys.

## Message Types
SPDB recognizes the following packet types by default:

```
+--------------+--------+--------------------------------------------------------------------------------+
| name         | number | description                                                                    |
+--------------+--------+--------------------------------------------------------------------------------+
| SEEK         | 0x00   | Announce that this node is looking for an endpoint                             |
+--------------+--------+--------------------------------------------------------------------------------+
| HAVE         | 0x01   | Reply that a path to the requested endpoint has been found                     |
+--------------+--------+--------------------------------------------------------------------------------+
| DEADPATH     | 0x02   | Indicates that the requested route is no longer available                      |
+--------------+--------+--------------------------------------------------------------------------------+
| GET          | 0x03   | A request the contents of an endpoint, while sending an optional public key    |
+--------------+--------+--------------------------------------------------------------------------------+
| MSG          | 0x04   | The contents of an endpoint                                                    |
+--------------+--------+--------------------------------------------------------------------------------+
| REKEY        | 0x05   | Negotiate a key change                                                         |
+--------------+--------+--------------------------------------------------------------------------------+
| PING         | 0x06   | Self-explanatory                                                               |
+--------------+--------+--------------------------------------------------------------------------------+
| PONG         | 0x07   | Self-explanatory                                                               |
+--------------+--------+--------------------------------------------------------------------------------+
```

Non-standard packets should always have packet type numbers of 0x40 or above.

The following describes each packet type and its fields.

---

SEEK

A SEEK packet is a way to find a route.
When a node receives a SEEK packet, it first looks at the path length and if it is too long, drops the packet. The path length of the packet is then incremented by the length of the connection between the node and the neighbor it got the SEEK from, with some random noise.
If the node can serve the endpointID, it replies with HAVE.
Otherewise, the node forwards the SEEK to every node for which it has forwarded a HAVE or MSG message for that EndpointID.
Otherwise, it forwards a SEEK containing the endpoint to a random neighbor who did not send the original SEEK and to whom no SEEK for that endpoint has been sent recently, and from who no DEADPATH for that endpoint has been received recently.
If no such neighbor exists, the node replies with DEADPATH.
Nodes periodically send out SEEK packets containing EndpointID's they seek, with a small random path length. They should not be repeated more than once a second, and nodes may wish to enforce this with throttling.


```
+----------------------+--------------------------------+
| payload max length   | 38 bytes                       |
+----------------------+--------------------------------+
| payload contents     | bytes 1-2: path length         |
|                      | remainder: sought EndpointID   |
+----------------------+--------------------------------+
| valid responses      | none                           |
+----------------------+--------------------------------+
| valid in-response-to | nothing                        |
+----------------------+--------------------------------+
```
NOTE: for heirarchally-shaped networks, it may be advantageous to only forward SEEKS in an "upward" direction.

---

HAVE

A HAVE packet is a response to a SEEK indicating that the endpoint has definitely been found.
It is forwarded in reverse order to the SEEK that it is in reply to. The path length starts at 0 and is incremented just like SEEKs.

```
+----------------------+-----------------------------------------------+
| payload max length   | 34 bytes                                      |
+----------------------+-----------------------------------------------+
| payload contents     | bytes 0-1: path length                        |
|                      | bytes 2-33: SHA256(SHA256(non-dynamic data))  |
+----------------------+-----------------------------------------------+
| valid responses      | none                                          |
+----------------------+-----------------------------------------------+
| valid in-response-to | SEEK,MSG,nothing                              |
+----------------------+-----------------------------------------------+
```

HAVE packets may be broadcast periodically with endpoints that this node can serve. They are forwarded randomly through the network.

---

GET

A GET packet is a request for a resource.
When a node recieves a GET packet, it checks if the path length is too long, if so the packet is dropped. Otherwise the path length is incremented.
If the node can serve the request, it replies with the appropriate resource.
If the node has seen an MSG with this endpoint, it forwards the GET to the upstream of that MSG
If the node has seen a HAVE with this endpoint, it forwards the GET to the upstream of that HAVE.
Otherwise it responds with DEADPATH.

```
+----------------------+--------------------------------+
| payload max length   | 1220 bytes                     |
+----------------------+--------------------------------+
| payload contents     | below                          |
+----------------------+--------------------------------+
| valid responses      | MSG,DEADPATH                   |
+----------------------+--------------------------------+
| valid in-response-to | nothing                        |
+----------------------+--------------------------------+
```

The payload of a GET packet:

```
+--------------+-------------------------------+
| size (bytes) | value                         |
+--------------+-------------------------------+
| 36           | EndpointID requested          |
+--------------+-------------------------------+
| 2            | sequence number               |
+--------------+-------------------------------+
| 16           | Reply-to address (0 for none) |
+--------------+-------------------------------+
| 2            | Reply-to port                 |
+--------------+-------------------------------+
| 16           | Reply-to nonce                |
+--------------+-------------------------------+
| 32           | Reply-to encryption key       |
+--------------+-------------------------------+
| 2            | public key type(0 for none)   |
+--------------+-------------------------------+
| <= 1024      | encryption public key         |
+--------------+-------------------------------+
| 90-1114      | additional request data       |
+--------------+-------------------------------+
```

The sequence number is used to specify that the stream should start at a specific part of the endpoint. This is useful for correcting dropped or out-of-order packets.
The length and encoding of the public key is determined by its 'type'. The only encryption public key type which must be supported by all nodes is Curve25519-ChaCha20-Poly1305, which has type 0x0001 and length 32 bytes.
If the reply-to address is 0, all the reply-to fields are ignored.

"additional request data" can be used to send arbitrary data, but it is not encrypted or verified by the protocol.

---

MSG

An MSG packet contains the data of an endpoint, or an encrypted channel. Their payload consists of two parts: an immutable hash-addressed part and a secondary part, which is usually signed and encrypted but not necessarily hashed.

```
+----------------------+--------------------------------+
| payload max length   | 1220 bytes                     |
+----------------------+--------------------------------+
|  payload contents    | below                          |
+----------------------+--------------------------------+
| valid responses      | GET,DEADPATH                   |
+----------------------+--------------------------------+
| valid in-response-to | GET                            |
+----------------------+--------------------------------+
```

payload format:
```
+--------------+-----------------------------------------------------+
| size (bytes) | value                                               |
+--------------+-----------------------------------------------------+
| 32           | SHA256 hash of non-dynamic data (first packet only) |
+--------------+-----------------------------------------------------+
| 2            | sequence number                                     |
+--------------+-----------------------------------------------------+
| 2            | next sequence number                                |
+--------------+-----------------------------------------------------+
| <= 1216      | contents                                            |
+--------------+-----------------------------------------------------+
```

The single-SHA256 is used instead of EndpointID to provide added assurance that the endpoint will not be faked. MSGs which do not provide the correct hash for the EndpointID are ignored.
The sequence number is used to order incoming packets. There is no required format other than that 0 uniquely represents the first part, and that if a sequence number is re-used it is only after 1024 other numbers have been used since.
If a node receives a sequence number out of order, it may send another GET down the line after a short timeout or after a certain number of packets (< 1024) have been received out of order

The type of endpoint is determined by the EndpointID. If the type is 10, the hashed data should have the following format:

```
+--------------+----------------------------+
| size (bytes) | value                      |
+--------------+----------------------------+
| 2            | encryption public key type |
+--------------+----------------------------+
| <= 1024      | encryption public key      |
+--------------+----------------------------+
| arbitrary    | additional hashed data     |
+--------------+----------------------------+
```

The dynamic portion of the endpoint would then be an AEAD tag and optionally a nonce defined by the encryption scheme, if any, followed by an encrypted portion. The nonce and AEAD tag (or other necessary encryption data) may not cross a packet boundary.
If the public key types of the endpoints are incompatible, the endpoint should return DEADPATH.
The dynamic data is decrypted and the 'additional hashed data' and the decrypted dynamic data are passed to the client.

If the endpoint type is 01, aka hashed data with a list of at most 32 servable linked EndpointIDs, each participant in the MSG tunnel should parse the list (presented as [EndpointID,double-hash] pairs) as if it was a sequence of HAVE packets, and the dynamic data is discarded from client output. The list of EndpointIDs may not cross a packet boundary.

If the endpoint type is 00, aka only hashed data, dynamic data is ignored and the MSG tunnel is closed when the hashed data is done transmitting

If the endpoint type is 11, the first bytes of hashed data should be a sequence of magic numbers indicating the extension type. If the extension is not recognized the raw stream is passed to the client.

It is also advised that GET-ing nodes generate a new keypair for each GET, to prevent replay attacks.

This scheme makes no guarantees about the identity of either endpoint, just that one side of the endpoint definitely has the hashed key, meaning that man-in-the-middle attacks are impossible. Identity should be verified with cryptographic signatures in the encrypted portion of a MSG.

Endpoints may choose to ignore the reply-to fields if they wish. When SPDB is not being used over a lower-level networking layer like IP then they are ignored.

After receiving the contents of an endpoint that they are willing and able to seed, nodes should send HAVE along the path they got the MSG from.

NOTE: MSG packets are the only multi-step things in the SPDB protocol. As such they need special provisions.
The reply-to nonce for a MSG should never change while serving one request. This means that no particular packet must be responded to, and allows for correcting dropped packets.
However, the MSG nonce itself also needs to change periodically, but sparsely enough that the program is resistant to dropped packets. Therefore, the nonce is changed every 1024 packets recieved in order, and is calculated by SHA256(previous nonce ++ payload of the first message received with the old nonce), truncated to 16 bytes. Messages with either the current nonce or the next nonce should be accepted.

---

REKEY

Re-keying is actually very simple in SPDB. For each neighbor, a node has at most two valid encryption keys. They can receive and process packets with either, but send with only one at a time.
Nodes will periodically re-key with each other, typically once per day. One node will first send a REKEY packet with a new key that may be used to encrypt packets to them. They wait for the other node to reply with a REKEY containing the same key. From then on, the new key is used for encryption as well as decryption. If no reply comes, it may be rebroadcast.

```
+----------------------+--------------------------------+
| payload max length   | 32 bytes                       |
+----------------------+--------------------------------+
|  payload contents    | Proposed key                   |
+----------------------+--------------------------------+
| valid responses      | REKEY                          |
+----------------------+--------------------------------+
| valid in-response-to | REKEY                          |
+----------------------+--------------------------------+
```

---

DEADPATH

A DEADPATH packet indicates that some previously-valid route is no longer valid, or that a GET has been cancelled.
When a node receives DEADPATH, it should forward the DEADPATH down the line and drop all state about that path.
```
+----------------------+--------------------------------+
| payload max length   | 0 bytes                        |
+----------------------+--------------------------------+
|  payload contents    | Proposed key                   |
+----------------------+--------------------------------+
| valid responses      | none                           |
+----------------------+--------------------------------+
| valid in-response-to | GET,MSG,SEEK                   |
+----------------------+--------------------------------+
```
