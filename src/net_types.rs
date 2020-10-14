use chacha20poly1305::{ChaCha20Poly1305,Tag,Key,Nonce};

type EndpointID = [u8;36];

impl EndpointID {
    fn type(&self) -> u8 {
        self[0] & 0xc0 != 0
    }

    fn hashed_length(&self) -> u32 {
        u32::from_be_bytes([self[0] & 0x3f,self[1],self[2],self[3]])
    }

    fn<'a> hash(&'a self) -> &'a[u8;32] {
        unsafe {
            mem::transmute((self as *const u8).offset(2isize))
        }
    }
}

//FNV-1a hash with an added truncation to a specific bit width
//n is the number of bits the hash should have
fn FNV1a(endpoint: &[u8;32], n: u32) -> u32 {
    let mut ret = 2166136261u32;
    for i in 0..32 {
        ret ^= endpoint[i];
        ret *= 16777619;
    }
    ret & (0xffffffff >> (32 - n)) //truncate the last bits
}

struct Node {
    addr: SocketAddr,
    send_key: [u8;32],
    recv_key1: [u8;32],
    recv_key2: [u8;32],
}

struct PathInfo {
    created: u64,
    node: Rc<Node>,
    endpoint: EndpointID,
}

//basic fixed-size hash table for paths
//hash collisions are resolved by evicting an element if and only if its age is more than min_age,
//if the element is not evicted the next is tried. Thus insertions and searches are O(n) but
//usually much faster
//unsafe code is used extensively because this is a core component that needs to be very very fast,
//and bounds checks are unnecessary because the structure is fixed-size once allocated
//use a u64 for age because I assume you won't leave the program on for hundreds of years
//the hash table has exactly 2^hash_bits elements.
//hash_bits must be less than 32 or all kinds of weird shit happens in unsafe code
//luckily that will probably never happen in practice because that would make a hash table
//approximately 230 gigabytes long
struct PathRememberer {
    paths: *mut PathInfo
    min_age: u64,
    hash_bits: u32,
    program_start: Instant
}

impl PathRememberer {
    fn new(hash_bits: u32, min_age: u64) -> PathRememberer {
        let (paths,_,_) = Vec::<PathInfo>with_capacity(1usize << hash_bits).into_raw_parts();
        PathRememberer {
            paths: paths,
            min_age: min_age,
            hash_bits: hash_bits,
            program_start: Instant::now()
        }
    }

    //returns true iff the path was inserted
    fn insert(&mut self, node: Rc<Node>, endpoint: EndpointID) -> bool {
        let index_0 = FNV1a(&endpoint,self.hash_bits);
        let rollover = (1u32 << self.hash_bits) - index_0;
        let current_time = self.program_start.elapsed().as_millis() as u64;
        let mut ctr:u32 = 0;
        unsafe {
            let mut index = self.path.offset(index_0 as isize);
	        while ctr < 1u32 << self.hash_bits {
	            if current_time - (*index).created >= min_age {
	                (*index) = PathInfo {
	                    created: current_time,
	                    node: node,
	                    endpoint: endpoint,
	                };
	                return true;
	            } else {
	                ctr += 1;
	                if ctr >= rollover {
	                    index = self.paths;
	                } else {
	                    index = index.offset(1isize);
	                }
	            }
	        }
        }
        false
    }

    //looks for a specific endpoint in the queue
    fn search(&self, endpoint: EndpointID) -> Option<Rc<Node>> {
        let index_0 = smaller_hash(&endpoint,self.hash_bits);
        let rollover = (1u32 << self.hash_bits) - index_0;
        let mut ctr:u32 = 0;
        unsafe {
            let mut index = self.path.offset(index_0 as isize);
            while ctr < 1u32 << self.hash_bits {
                if (*index).endpoint == endpoint {
                    return Some(Rc::clone((*index).node));
                } else {
                    ctr += 1;
                    if ctr >= rollover {
                        index = self.paths;
                    } else {
                        index = index.offset(1isize);
                    }
                }
            }
        }
        None
    }

    //removes an element, for instance if there was a DEADPATH
    //this is simply done by clearing the EndpointID and created fields
    fn remove(&mut self, endpoint: EndpointID, node: Rc<Node>) -> bool {
        let index_0 = smaller_hash(&endpoint,self.hash_bits);
        let rollover = (1u32 << self.hash_bits) - index_0;
        let mut ctr:u32 = 0;
        unsafe {
            let mut index = self.path.offset(index_0 as isize);
	        while ctr < 1u32 << self.hash_bits {
	            if (*index).endpoint == endpoint && (*index).node.ptr_eq(node) {
	                (*index).endpoint = [0u8;36];
	                (*index).created = 0;
	                return true;
	            } else {
	                ctr += 1;
	                if ctr >= rollover {
	                    index = self.paths;
	                } else {
	                    index = index.offset(1isize);
	                }
	            }
            }
        }
        false;
    }
}

impl Drop for PathRememberer {
    fn drop(&mut self) {
        unsafe {
            let badoobidie = Vec::from_raw_parts(paths,1usize << self.hash_bits, 1usize << self.hash_bits);
        }
    }
}

#[repr(u8)]
enum PacketType {
    SEEK,
    HAVE,
    DEADPATH,
    GET,
    MSG,
    REKEY,
    PING,
    PONG
}

#[derive(Hash)]
type ResponseTag = ([u8;16],MsgType);

type PacketHeader = [u8;36];

impl PacketHeader {
    fn<'a> nonce(&'a self) -> &'a [u8;16] {
        unsafe {
            mem::transmute(self[0..16] as *const u8)
        }
    }
    fn<'a> reply_nonce(&'a self) -> &'a [u8;16] {
        unsafe {
            mem::transmute(self[16..32] as *const u8)
        }
    }
    fn type(&self) -> PacketType {
        self[32] as PacketType
    }
    fn flags(&self) -> u8[
        self[33]
    ]
    fn payload_len(&self) -> u16 {
        u16::from_be_bytes([self[34],self[35]])
    }
}

//convenience functions for extracting relevant data from the default-size UDP buffer
fn<'a> extract_header(buffer: &'a [u8;1272]) -> &'a PacketHeader {
    unsafe {
        mem::transmute(buffer as *const u8)
    }
}

fn<'a> extract_payload(buffer: &'a mut [u8;1272]) -> &'a mut [u8] {
    let payload_len = extract_header(buffer).payload_len();
    buffer[36..36+payload_len]
}

fn<'a> extract_aead(buffer: &'a [u8;1272]) -> &'a [u8;16] {
    unsafe {
        let mut p = buffer as *const u8;
        mem::transmute(p.offset(1256isize))
    }
}

//allocates a buffer from the heap and turns it into a reference to a fixed size array
fn alloc_fixed_buf() -> &'static mut [u8;1272] {
    let v: Vec<u8> = Vec::with_capacity(1272);
    unsafe {
        mem::transmute(v.into_raw_parts().0)
    }
}

//explicitly de-allocates a buf created as above
fn dealloc_fixed_buf(buf: &'static mut [u8;1272]) {
    unsafe {
        let badoobidie = Vec::from_raw_parts(buf as *mut u8,1272,1272);
    }
}

struct MessageChunk {
    next_seq: u16,
    data: Vec<u8>
}

impl MessageChunk {
    fn new() -> MessageChunk {
        MessageChunk {
            next_seq: 0,
            data: Vec::new()
        }
    }

    fn from_data(data: &[u8], next_seq: u16) -> MessageChunk {
        let mut new_data = Vec::with_capacity(data.len());
        new_data.copy_from_slice(data);
        MessageChunk {
            next_seq: next_seq,
            data: new_data
        }
    }
}

//keeps track of a currently-streaming message
struct MessageTracker {
    endpoint: EndpointID,
    next_seq: u16,
    out_of_order_chunks: HashMap<u16,MessageChunk>,
    hasher: Sha256,
    data_recieved: u32,
    chunks_recieved: u32,
    hashed_data_size: u32,
    hash: [u8;32],
    stream_aead: Option<(Key,Nonce,Tag)>, //maybe not this...
    remote_key: [u8;32],
    current_nonce: [u8;16],
    next_nonce: [u8; 16],
    output_stream: TcpStream
}

const OUT_OF_ORDER_BUFFER_SIZE: usize = 128;

//tries to piece together message chunks
fn<'a> piece_message_chunks(chunks_to_check: &'a HashMap<u16,MessageChunk>, start_seq: u16) -> Vec<&'a Vec<u8>> {
    let mut ret: Vec<&'a Vec<u8>>
    let mut seq = next_seq;
    loop {
        if let Some(chunk) = chunks_to_check.get_mut(seq) {
            if (chunk.seq != 0) {
                seq = chunk.next_seq;
                chunk.next_seq = 0;
                ret.push(&chunk.data);
            }
        } else {
            break;
        }
    }
    ret
}

impl MessageTracker {
    fn new(endpoint: EndpointID, stream: TcpStream, local_key: [u8;32]) -> MessageTracker {
        let hashed_size = endpoint.hashed_length();
        MessageTracker {
            endpoint: endpoint,
            next_seq: 0,
            out_of_order_chunks: HashMap::new(),
            hasher: Sha256::new(),
            data_recieved: 0,
            chunks_recieved: 0,
            hashed_data_size: hashed_size,
            stream_aead: None,
            current_nonce: [0;16],
            next_nonce: [0; 16],
            output_stream: TcpStream
        }
    }

    //reinitialize a stream from a new chunk. This amounts to clearing out_of_order_chunks and
    //resetting last_1024_chunk
    fn reinitialize(&mut self, new_nonce: [u8;16]) {
        self.out_of_order_chunks.clear();
        self.current_nonce = [0;16];
        self.next_nonce = new_nonce;
    }

    //process the first packet
    //returns Ok if the packet is valid and there was no error, Err otherwise
    fn process_first_packet(&mut self, packet: &[u8;1272]) -> Result<()> {
    }

    //try to process a new packet that is *not* the first packet
    //returns Ok(None) if the packet was processed and the nonce didn't change
    //returns Ok(Some(nonce)) if the packet was processed and a new nonce is now valid for this
    //stream. The old nonce should be dropped
    //returns Err if either the Tcp output failed or the out_of_order_chunks queue got too big
    fn process_new_packet(&mut self, packet: &mut [u8;1272]) -> Result<Option<[u8;16]>> {
        let payload = extract_payload(packet);
        let this_seq = u16::from_be_bytes([payload[0],payload[1]]);
        let next_seq = u16::from_be_bytes([payload[2],payload[3]]);
        if this_seq == self.next_seq {
            let end = (data_received + payload.len()) % self.endpoint.hashed_length();
            if data_received < self.endpoint.hashed_length() {
                hasher.input(payload[4..end]);
                output_stream.write(payload[4..end])?;
            } else if end < payload.len() {
                if self.endpoint.type() == 0x2 {
                    if let Some((key,nonce,tag)) = self.stream_aead {
                        ChaCha20Poly1305::decrypt_in_place_detatched(nonce,)
                    } else { 
                        panic!("you are using the MessageTracker struct wrong")
                    }
                } else if self.endpoint.type() == 0x1
            }
            self.next_seq = next_seq;
            self.chunks_recieved += 1;
            let mut nonce_changed = false;
            if self.chunks_recieved.trailing_zeros() == 9 { //we want this to trigger every 2^10 packets processed
                let mut new_nonce_hasher = Sha256::new();
                self.current_nonce.copy_from_slice(self.next_nonce);
                new_nonce_hasher.input(&self.next_nonce);
                new_nonce_hasher.input(&payload);
                new_nonce_hasher.output(&mut self.next_nonce);
                nonce_changed = true;
            }
            let ordered_chunks = piece_message_chunks(&mut self.out_of_order_chunks, next_seq);
            for chunk in ordered_chunks {
                if self.endpoint.type() == 0x2 {
                    //TODO: decryption
                }
                //TODO: hash the input and handle changing the nonce
                output_stream.write(chunk)?;
            }
            if stream.len() == self.out_of_order_chunks.len() {
                self.out_of_order_chunks.clear();
            } else {
                self.out_of_order_chunks.retain(|c| { c.next_seq != 0 });
            }
            if nonce_changed {
                Ok(self.next_nonce)
            } else {
                Ok(None)
            }
        } else if self.out_of_order_chunks.len() < OUT_OF_ORDER_BUFFER_SIZE {
            self.out_of_order_chunks.insert(this_seq,MessageChunk::from_data(payload[4..],next_seq);
            Ok(false)
        } else {
            Err
        }
    }
}
