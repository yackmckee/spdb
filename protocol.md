# SPDB
## SPeeDyBase

SPDB is a simple network, designed to be very fast(implied by the name) and highly adaptable to many use-cases. It supports exchanging hash-addressed immutable blocks of data, as well as creating signed and encrypted data channels and providing weak anonymity guarantees.

The primary use-case of SPDB is as a server-side utility similar to IPFS gateways, but flexible enough to meet many different needs.

## Design Goals

The design goals of SPDB are pretty simple:
SPDB should be
- fast: implied by the name. The primary goal of speediboi is to be significantly faster than other distributed databases at scale. Particularly, if a block has been fetched it should be very fast to fetch all linked blocks.
- scalable: the network should be no more congested with a billion nodes than a thousand
- reliable: it should be uncommon for an endpoint lookup to fail if the endpoint is not far away in the network
- low-resources: I should be able to run speediboi on a toaster
- network- and operating system-agnostic: there should be as few assumptions as possible on the underlying network protocols.
- resilient to DOS attacks

The main routing model is F2F. Nodes must exchange keys and contact information out-of-band to participate in the network. There are a few reasons for this:
1) SPDB is intended to protect the users' privacy. By exchanging keys out-of-band and having no handshake protocols it is made difficult to detect when SPDB is being used.
2) By not enforcing any particular method of exchanging contact information, SPDB can be used in a variety of contexts. File-sharing networks may desire to use a DHT, website administrators may desire to have 'coordinator' nodes, friends may just want to connect to their friends.
3) DOS and Sibyl attacks are mitigated by never accepting messages from 'un-vetted' peers
4) Issues of trust between nodes are turned into issues of trust between operators, which may be very different in different contexts
5) Public-key cryptography is computationally expensive and vulnerable to quantum computers. It is used by SPDB only when no alternative exists.

Currently, SHA256 is the preferred hashing function. This may change in the future if weaknesses are found.

## Message Format Description

The protocol assumes that UDP and TCP are available and distinguishes between them, however, any transport protocols which offer the same guarantees are usable. In fact, TCP messages are *only* uni-directional and short-lived, so more lax protocols like muTP could be used.
SPDB is designed with IPv6 in mind, and the IPv6 minimum MTU of 1280 bytes is assumed to be the MTU of all paths.
All integers are in big-endian and are unsigned unless specified otherwise.
All message payloads are padded with random data. UDP messages are padded to the MTU. TCP messages are padded with a random amount of data less than one quarter of their payload length.
All messages have the following format:

```
+----------------------------------------+
| nonce: 16 bytes                        |
+----------------------------------------+
| AEAD tag: 16 bytes                     |
+----------------------------------------+
| nonce for reply: 16 bytes              |
+----------------------------------------+
| message type: 1 byte                   |
+----------------------------------------+
| flags: 1 byte                          |
+----------------------------------------+
| payload length: 4 bytes                |
+----------------------------------------+
| payload                                |
+----------------------------------------+
```

Everything after the nonce and AEAD tag are encrypted with the appropriate nonce and key.
Nonces are sent along with every message even when not technically necessary, as they serve to identify responses.

## Message Flags
Flags send extra info about how the message should be routed/handled.

```
+------+---------------+
| mask | meaning       |
+------+---------------+
| 0x01 | keep-alive    |
+------+---------------+
```

non-standard flags should have masks of 0x10 or higher.

## NodeID's
To meet different needs, NodeID's can be exchanged with node contact information or not. If a node does not have a self-assigned NodeID, it is assumed to be SHA256(underlying link identifier). The most common underlying link id would be IP address and port, always encoded as IPv6 and with port after IP.

## EndpointID's
EndpointID's are calculated using hashes of the data at the endpoint. They are 36 bytes long, the first 4 bytes being an unsigned int which is the amount of the message that must hash to the remaining 32 bytes.
EndpointID's provide a weak form of identity. Primarily, they are used for the following two use-cases: exchanging immutable blocks of hash-addressed data, and exchanging public keys.
Only the last 32 bytes are used when finding the distance between a NodeID and a EndpointID.

## Message Types
SPDB recognizes the following message types by default:

```
+--------------+--------+--------------------------------------------------------------------------------+
| name         | number | description                                                                    |
+--------------+--------+--------------------------------------------------------------------------------+
| SEEK         | 0x01   | Announce that this node is looking for a particular set of messages            |
+--------------+--------+--------------------------------------------------------------------------------+
| GET          | 0x02   | A request a message, while sending an optional public key                      |
+--------------+--------+--------------------------------------------------------------------------------+
| MSG          | 0x03   | A message                                                                      |
+--------------+--------+--------------------------------------------------------------------------------+
| ANNOUNCE     | 0x04   | Announce that this node knows how to reach some set of messages                |
+--------------+--------+--------------------------------------------------------------------------------+
| REKEY        | 0x05   | Negotiate a key change                                                         |
+--------------+--------+--------------------------------------------------------------------------------+
| DEADPATH     | 0x06   | Indicates that the requested route is no longer available                      |
+--------------+--------+--------------------------------------------------------------------------------+
```

Non-standard messages should always have message type numbers of 0x40 or above.

The following describes each message type and its fields.

---

SEEK

A SEEK message is forwarded through the network in gossip style, indicating that the sending node is looking for a particular set of messages. As many message ID's as possible should always be put into a SEEK request.
SEEK messages are only sent when a node is either directly seeking one of the EndpointID's, or when it receives a SEEK message.
When a node receives a SEEK message, it should immediately add all the blocks in the message to its seeking-queue. It then selects the top 32 blocks from the queue which have not been recently sent(by some measure), and sends a new SEEK message to the neighbor which is closest to any of the blocks in the message. Note that the new SEEK message doesn't necessarily contain any of the EndpointID's from the SEEK it just recieved.
Nodes periodically send out SEEK messages containing EndpointID's they seek. They should not be repeated more than once a second, and nodes may wish to enforce this with throttling.

```
+----------------------+--------------------------------+
| payload max length   | 1210 bytes                     |
+----------------------+--------------------------------+
| payload contents     | byte 1: number of sought ID's  |
|                      | remainder: list of sought ID's |
+----------------------+--------------------------------+
| valid responses      | none                           |
+----------------------+--------------------------------+
| valid in-response-to | nothing                        |
+----------------------+--------------------------------+
| protocol             | UDP                            |
+----------------------+--------------------------------+
```

The 'sought ID's' are encoded like so:

```
+------------+-------------+-------------+------------+
| byte range | 0           | 1-2         | 3-38       |
+------------+-------------+-------------+------------+
| value      | hop counter | path length | EndpointID |
+------------+-------------+-------------+------------+
```

EndpointID's are sorted by path length in the seeking-queue. When a EndpointID is added to the seek-queue, its hop counter is incremented by a random value in [1,16], and its path length is set to ((old path length)\*(old hop count) + ((neighbor path length)\*(random integer in [1,16])))/(new hop length). Both are intialized to 0.
The neighbor path length should be the round-trip time of the last ANNOUNCE ping that was sent, in milliseconds.


---

ANNOUNCE

An ANNOUNCE message has the exact same structure as a SEEK message, but means an entirely different thing.
Nodes periodically exchange ANNOUNCE messages as pings. It is expected that the recipient node will immediately reply with their own ANNOUNCE. Like SEEKs, the contents of these ANNOUNCE messages should be blocks that have not been recently ANNOUNCEd, and at least one of them should have a EndpointID for which the recipient is the closest neighbor.
Nodes not only keep a list of which messages they themselves can provide, but also a list of messages they have recieved from other ANNOUNCE messages. These are stored and prioritized just like the seeking-queue.
When a node recieves EndpointID in a SEEK message that appears in their announcing-queue, they should immediately send an ANNOUNCE ping(but not a reply) that contains those EndpointIDs.
When a node receives an ANNOUNCE message containing a EndpointID that is in their seeking queue, but which they themselves are not seeking, they should immediately send an ANNOUNCE ping to the neighbor who sought those EndpointIDs, containing those EndpointIDs. The EndpointID's should then be added to the announce-queue and dropped from the seeking-queue.

```
+----------------------+--------------------------------+
| payload max length   | 1210 bytes                     |
+----------------------+--------------------------------+
| payload contents     | byte 1: number of ID's         |
|                      | remainder: list of ID's        |
+----------------------+--------------------------------+
| valid responses      | ANNOUNCE                       |
+----------------------+--------------------------------+
| valid in-response-to | nothing                        |
+----------------------+--------------------------------+
| protocol             | UDP                            |
+----------------------+--------------------------------+
```

---

GET

A GET message is a request for a specific resource, with some optional data to be used for either routing or key exchange.
When a node recieves a GET message that is not in their announce-queue, they should reply with DEADPATH.
If the node itself can serve the GET, it replies with an MSG. The details of what this MSG should contain vary.
Otherwise, they should forward the message to the next hop in the path as indicated by their announce-queue, and keep state to eventually forward a MSG or DEADPATH message back if the reply-to address is zero. This state will be deleted after an appropriate timeout(5 seconds is recommended). TCP connections for this forwarding are not kept open for multiple messages unless keep-alive is enabled. Nodes should strip keep-alive if they do not respect it.

```
+----------------------+--------------------------------+
| payload max length   | 1226 bytes                     |
+----------------------+--------------------------------+
| payload contents     | below                          |
+----------------------+--------------------------------+
| valid responses      | MSG,DEADPATH                   |
+----------------------+--------------------------------+
| valid in-response-to | nothing                        |
+----------------------+--------------------------------+
| protocol             | UDP                            |
+----------------------+--------------------------------+
```

The payload of a GET message:

```
+--------------+-------------------------------+
| size (bytes) | value                         |
+--------------+-------------------------------+
| 36           | EndpointID requested          |
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
| <= 1154      | encryption public key         |
+--------------+-------------------------------+
```

The length and encoding of the public key is determined by its 'type'. The only encryption public key type which must be supported by all nodes is Curve25519-ChaCha20-Poly1305, which has type 0x0001 and length 32 bytes.
If the reply-to address is 0, all the reply-to fields are ignored

---

MSG

An MSG message contains a higher-level "message" object, which is what the user actually sees as output. Their payload consists of two parts: an immutable hash-addressed part and a secondary part, which is usually signed and encrypted but not necessarily hashed.
MSG's can be exchanged an arbitrary number of times in response to each other, but this is highly discouraged.

```
+----------------------+--------------------------------+
| payload max length   | 2^32 bytes                     |
+----------------------+--------------------------------+
|  payload contents    | EndpointID                     |
|                      | hashed data                    |
|                      | un-hashed data                 |
+----------------------+--------------------------------+
| valid responses      | MSG,DEADPATH                   |
+----------------------+--------------------------------+
| valid in-response-to | GET,MSG                        |
+----------------------+--------------------------------+
| protocol             | TCP                            |
+----------------------+--------------------------------+
```

There are fundamentally two kinds of endpoint. The first kind has a payload which is simply the requested hashed data, and the unhashed part is a list of EndpointIDs (at most 32) which this node can also serve. They are processed like they would be in an ANNOUNCE message by all nodes participating in the path.
The second kind contains public key information in the hashed part, and encrypted+signed data in the un-hashed part. The hashed part should look like this:

```
+--------------+----------------------------+
| size (bytes) | value                      |
+--------------+----------------------------+
| 2            | encryption public key type |
+--------------+----------------------------+
| <= 1154      | encryption public key      |
+--------------+----------------------------+
```

The remainder of the message would then be an AEAD tag and optionally a nonce defined by the encryption scheme, if any, followed by an encrypted portion.
If the public key types of the endpoints are incompatible, the endpoint should return DEADPATH.
There is no required format for the encrypted portion, but it should include a new random nonce which is to be used for the reply if there is going to be any, as well as a random amount of random padding.

MSG's may be freely sent with the same EndpointID and hashed data, encrypted using the shared secret. It is advised to never exchange more than two MSG's before killing the path.
It is also advised that GET-ing nodes generate a new keypair for each GET, to prevent replay attacks.

This scheme makes no guarantees about the identity of either endpoint, just that one side of the endpoint definitely has the hashed key, meaning that man-in-the-middle attacks are impossible. Identity should be verified with cryptographic signatures in the encrypted portion of a MSG.

Endpoints may choose to ignore the reply-to fields if they wish.

After GETing a block of hashed data that they are prepared to seed, nodes should ANNOUNCE that they can serve it with 0 hops and 0 path length.

---

REKEY

Re-keying is actually very simple in SPDB. For each neighbor, a node has at most two valid encryption keys. They can receive and process messages with either, but send with only one at a time.
Nodes will periodically re-key with each other, typically once per day. One node will first send a REKEY message with a new key that may be used to encrypt messages to them. They wait for the other node to reply with a REKEY containing the same key. They then reply with an ANNOUNCE ping using the new key and forget the old one, and the other node forgets the old key when the ANNOUNCE ping is replied to.
If a node receives a REKEY message containing a different key from the one they are re-keying with, they drop their new key and reply with the one they just got.

```
+----------------------+--------------------------------+
| payload max length   | 32 bytes                       |
+----------------------+--------------------------------+
|  payload contents    | Proposed key                   |
+----------------------+--------------------------------+
| valid responses      | REKEY,ANNOUNCE                 |
+----------------------+--------------------------------+
| valid in-response-to | REKEY                          |
+----------------------+--------------------------------+
| protocol             | UDP                            |
+----------------------+--------------------------------+
```

---

DEADPATH

A DEADPATH message indicates that some previously-ANNOUNCEd path should no longer be considered valid. This prevents no-longer-valid paths from cluttering the network and is also a signal for an endpoint just not being available.
When a node receives DEADPATH in response to a GET request, it should forward the DEADPATH down the line if and only if no other path is known, otherwise it should try to forward the GET to a new path.
DEADPATHs in response to GETs always cause the dead path to be pruned from memory. A DEADPATH in response to MSG does not cause this behavior, and should simply be forwarded and cause state to be dropped.

```
+----------------------+--------------------------------+
| payload max length   | 0 bytes                        |
+----------------------+--------------------------------+
|  payload contents    | Proposed key                   |
+----------------------+--------------------------------+
| valid responses      | none                           |
+----------------------+--------------------------------+
| valid in-response-to | GET,MSG                        |
+----------------------+--------------------------------+
| protocol             | UDP                            |
+----------------------+--------------------------------+
```

## Some notes on flow control
Generally, every node in a forwarding chain should implement some kind of flow control. An internal buffer should be kept, which all MSG messages should be required to fill up before they are decrypted, re-encrypted, and passed down the line. This prevents malicious tuning of flow. 