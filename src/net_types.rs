use std::time::{Duration,Instant,SystemTime,UNIX_EPOCH};
#![feature(map_first_last)]
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use rand_core::RngCore;
use crypto::Pubkey;
use sha2::{Sha256, Digest};

struct EndpointID {
    length: u32,
    hash: [u8; 32]
};

impl EndpointID {
    fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < 36 {
            Err
        } else {
            buf[0..4].copy_from_slice(&self.length.to_be_bytes());
            buf[4..36].copy_from_slice(&self.hash);
            Ok(())
        }
    }

    fn decode(encoded: [u8;36]) -> EndpointID {
        EndpointID {
            length: u32::from_be_bytes([encoded[0],encoded[1],encoded[2],encoded[3]]),
            hash: [u8 ;32]::<&[u8]>try_from(&encoded[4..36])
        }
    }
}

type NodeID = [u8; 32];

pub struct Node {
    IP: SocketAddr,
    ID: NodeID,
    current_key: [u8;32],
    new_key: Option<[u8;32]>,
    last_ping: Instant,
};

struct HalfPath {
    num_hops: u8,
    next_hop: u16,
    endpoint: EndpointID,
};


//distance between a NodeID and an EndpointID, calculated by the inverse of the number of bits
//which match at the start
pub fn dist(endpoint: &EndpointID, node: &NodeID) -> u32 {
    let mut ret: u32 = 0;
    for i in 0..32 {
        if endpoint.hash[i] == node[i] {
            ret += 8;
        } else {
            ret += (endpoint.hash[i] ^ node[i]).leading_zeroes();
            break;
        }
    }
    32 - ret;
}

//this queue is not for finding routes; it should instead be used for 
//does not guarantee that paths stored in the queue are unique; we do this using the RoutingTable
//uses a fixed amount of memory
pub struct PathQueue {
    queue: BTreeMap<u64,HalfPath>, //we store in the u32 the path length and a "unique identifier" which is generated from a timestamp
    max_size: usize,
    cursor: u64
};

impl PathQueue {
    pub fn new(max_size: usize) -> AnnounceQueue {
        let max_entries = max_size/(std::mem::size_of::<HalfPath>() + 8); //assumes that memory usage is exactly the size of the blocks; adjust for the constant multiple
        HalfPathQueue {
            queue: BTreeMap::new(),
            max_size: max_entries,
            cursor: 0
        }
    }

    //insert a halfpath into the queue
    //assumes that the hops and length have already been incremented by random values
    //returned value is the 'path id', and optionally the next hop and EndpointID of the path that was removed
    //O(log m)
    pub fn insert<R: RngCore>(&mut self, new_element: HalfPath, new_element_path_length: u16, rng: &mut R) -> (u64,Option<u16,EndpointID>) {
        let new_id = ((new_element_path_length as u64) << 48) | (rng.next_u64() & 0xffffffffffff);
        if self.queue.len() < self.max_size {
            self.queue.insert(new_id,new_element);
            (new_id,None)
        } else {
            self.queue.insert(new_id,new_element);
            let (k,v) = self.queue.last_key_value().unwrap(); //why is this experimental??? also, this never panics, because self.queue is guaranteed non-empty
            self.queue.remove(k);
            if *k == self.cursor {
                self.cursor = 0;
            }
            (new_id,Some(*v.next_hop,*v.endpoint))
        }
    }

    //get a new chunk of <= n Halfpaths and copy them into a buffer, returning the number
    //of bytes copied. Returns an error if the buffer is too small, or if the queue is empty
    //O(n log m)
    pub fn get_chunk(&mut self, buf: &mut [u8], n: usize) -> Result<usize> {
        if buf.len() < n*39 || self.queue.is_empty() {
            Err
        } else {
            let mut copy_ctr: usize = 0;
            for (key,path) in self.queue.range(self.cursor..).take(n) {
                buf[copy_ctr] = path.num_hops;
                buf[(copy_ctr+1)..(copy_ctr + 3)].copy_from_slice(key.to_be_bytes()[0..2]);
                path.endpoint.encode(&mut buf[(copy_ptr+3..copy_ptr+39)])?;
                copy_ctr += 39;
                self.cursor = key + 1;
            }
            if self.cursor > *self.queue.last_key_value().unwrap().0 { //never panics, queue is never empty
                self.cursor = 0;
            }
            Ok(copy_ctr)
        }
    }

    //remove a specific endpoint from the queue
    pub fn remove(&mut self, endpoint_id: u64) {
        self.queue.remove(&endpoint_id);
    }

}

//holds routing information.
pub struct RoutingTable {
    neighbors: Vec<(Node,u16,HashMap<EndpointID,u64>)>,
};

impl RoutingTable {

    //it is a good idea to give a max_size on the conservative side, to avoid re-allocations
    pub fn new(nodes: Vec<Node>, max_size:usize) -> RoutingTable {
        let max_len = max_size/((36 + 8) * nodes.len());
        let neighbors: Vec<(Node,u16,HashMap<EndpointID,u16>)> = nodes.iter().map(|n| {
                                                                     (n,0,HashMap::with_capacity(max_len))
                                                                 }).collect();
        RoutingTable {
            neighbors: neighbors
        }
    }

    //adds a new path from the given neighbor(next_hop) and given parameters
    pub fn add_path<R: RngCore>(&mut self, queue: &mut PathQueue, next_hop: u16, path_length: u16, num_hops: u8, endpoint: EndpointID, rng: &mut R) {
        //first, fudge the hops and path length
        let hop_incr = ((rng.next_u32() >> 28) + 1); //normalize all values to between 1 and 17
        let path_length_mult = ((rng.next_u32() >> 28) + 1); //again, normalize to between 1 and 17
        let new_hops = num_hops + hop_incr as u8;
        let new_path_length = (((path_length as u32)*num_hops + (self.neighbors[next_hop as usize].1 as u32)*path_length_mult)/(new_hops as u32)) as u16;
        //add into the announce queue
        let (new_path_id,maybe_dropped_path) = queue.insert(HalfPath { num_hops: new_hops,
                                                                                next_hop: next_hop,
                                                                                endpoint: endpoint },
                                                                     new_path_length,
                                                                     rng);
        //if a path was dropped, drop it from the routing table too
        match maybe_dropped_path {
            Some((node_id,endpoint)) => self.neighbors[node_id as usize].2.remove(endpoint);
            None => ()
        };
        //now add the new path to the routing table
        let maybe_replaced_id = self.neighbors[next_hop as usize].2.insert(endpoint,new_path_id);
        //if we already had a path through that neighbor, we want to specifically replace it.
        if let Some(replaced_id) = maybe_replaced_id {
            queue.remove(*replaced_id);
        }
    }

    //removes a specific path from the routing table
    pub fn remove_path(&mut self, queue: &mut PathQueue, next_hop: u16, endpoint: &EndpointID) {
        let maybe_this_path_id = self.neighbors[next_hop as usize].2.get(endpoint);
        if let Some(this_path_id) = maybe_this_path_id {
            queue.remove(this_path_id);
            self.neighbors[next_hop as usize].2.remove(endpoint);
        }
        //if there was no id in the routing table in the first place, we gucci
    }

    //get the node with the shortest path to an endpoint, if any exists
    pub fn get_path(&self, endpoint: &EndpointID) -> Option<Node> {
        let mut shortest_path: u64 = 0xffffffffffffffff;
        let mut shortest_path_index: usize = self.neighbors.len() + 1;
        for (i, (_,_,table)) in self.neighbors.iter().enumerate() {
            if let Some(path_id) = table.get(endpoint) {
                if path_id < shortest_path { //upper 16 bits are exactly the 'path length', so ordering is preserved
                    shortest_path = path_id;
                    shortest_path_index = i;
                }
            }
        }
        if shortest_path_index < self.neighbors.len() {
            Some(neighbors[shortest_path_index].0)
        } else {
            None
        }
    }

    //checks for the mere existence of a path.
    pub fn path_exists(&self, endpoint: &EndpointID) -> bool {
        for (_,_,table) in self.neighbors.iter() {
            if table.contains(endpoint) {
                return true;
            }
        }
        false
    }

    //update the ping timing of one of the neighbors
    pub fn update_ping(&mut self, which_node: usize, new_time: u16) {
        self.neighbors[which_node].1 = new_time;
    }

    //let a new key be used
    pub fn rekey_part1(&mut self, which_node: usize, new_key: [u8;32]) {
        self.neighbors[which_node].0.new_key = Some(new_key);
    }

    //erase old key
    pub fn rekey_part2(&mut self, which_node: usize) -> bool {
        if let Some(new_key) = self.neighbors[which_node].0.new_key {
            self.neighbors[which_node].0.current_key = new_key;
            self.neighbors[which_node].0.new_key = None;
            true
        } else {
            false
        }
    }

    //get a node
    pub fn get_neighbor(&self, which: usize) -> Node {
        self.neighbors[which].0
    }
}

//holds information necessary to be a non-end link in a forwarding path
pub struct ForwardData {
    from_node: Node,
    from_recv_nonce: [u8; 16],
    from_send_nonce: [u8; 16],
    to_endpoint: EndpointID,
    to_node: Option<Node>,
    to_recv_nonce: [u8; 16],
    to_send_nonce: [u8; 16],
    GET_data: Vec<u8>,
    crypt_buffer: Option<Vec<u8>,
    msg_tag: Option<Vec<u8>>,
    hasher_state: Sha256,
    TCP_stream: Option<Box<TcpStream>>
};

//

#[repr(u8)]
pub enum MessageType {
    SEEK = 1,
    GET = 2,
    MSG = 3,
    ANNOUNCE = 4,
    REKEY = 5,
    DEADPATH = 6,
};


