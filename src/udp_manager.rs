//this file contains code which manages all state for SPDB events.
//also contains the udp_listen, which is the loop handling incoming UDP traffic
//UDP messages are all handled synchronously, since there is no significant computation involved in
//any of them
use net_types::{EndpointID,NodeID,RoutingTable, MessageType, PathQueue};
use rand_core::RngCore;
use rand_isaac::isaac::Isaac64Rng;
use getrandom::getrandom;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead}
use std::collections::HashMap;
use tokio::sync::{Mutex,RwLock}


async fn udp_listen(listen_address: SocketAddr, announce_queue: Arc<Mutex<PathQueue>>, seeking_queue: Ac<RwLock<PathQueue>>, waiting_replies: Arc<Mutex<HashMap<([u8;16],u16),ReplyData>>>, neighbors: Arc<RwLock<RoutingTable>>, endpoints_to_serve: Arc<RwLock<EndpointManager>>, mem_limit: usize) -> Result<()> {
    let mut seeking_queue = PathQueue::new(mem_limit/10);
    let mut listener = UdpSocket::bind(listen_address)?;
    let mut buf: [u8; 1272] = [0;1272];
    let mut current_seed_bytes: [u8;8] = [0;8];
    let mut current_reseed_bytes: [u8;4] = [0;4]; 
    let mut random_reseed_ctr: u32 = 0;
    let mut random_reseed: u32 = 0;
    let mut this_rng = Isaac64Rng::seed_from_u64(0);
    loop {
        //reseed the rng if necessary
        if random_reset_ctr == random_reseed {
            getrandom(&mut current_seed_bytes);
            getrandom(&mut current_reseed_bytes);
            random_reseed = u32::from_bytes(current_reseed_bytes);
            random_reseed_ctr = 0;
            this_rng = Isaac64Rng::seed_from_u64(u64::from(current_seed_bytes));
            current_seed_bytes = [0;8];
        }
        //receive a packet and see who it came from
        let (num_read, addr) = listener.recv_from(&mut buf).await?;
        let node_index = if let Some(i) = neighbors.read().await.find_neighbor_index(addr) {
            i
        } else {
            continue; //break the loop, but rust will complain if we don't return something here too
            0
        }
        //decrypt and verify the message
        let node = neighbors.read().await.get_neighbor(node_index);
        let nonce = buf[0..16];
        let cipher_try1 = ChaCha20Poly1305::new(Key::from_slice(&node.current_key));
        let try1 = cipher_try1.decrypt(nonce,buf[16..]);
        let mut decrypted_buf: Vec<u8> = Vec::new();
        if try1.is_err() && node.new_key.is_some() {
            let cipher_try2 = ChaCha20Poly1305::new(Key::from_slice(&node.new_key.unwrap()));
            decrypted_buf = cipher_try2.decrypt(nonce,buf[16..])?;
        } else if try1.is_err() {
            return Err(try1.err())
        } else {
            decrypted_buf = try1.unwrap();
        }
        let response_nonce = decrypted_buf[0..16] as &[u8;16];
        let msg_type = MessageType(decrypted_buf[16]);
        let msg_flags = decrypted_buf[17] as usize;
        let msg_len = u32::from_le_bytes([decrypted_buf[18],decrypted_buf[19],decrypted_buf[20],decrypted_buf[21]]);
        let payload = decrypted_buf[22..(22+(msg_len as usize))];
        let mut response_buf: [u8;1272] = [0;1272]; //stores the response. We build everything in-place to avoid allocations
        match msg_type {
            MessageType::ANNOUNCE => {
                //keeps track of which things in this ANNOUNCE message we are seeking
                let mut endpoints_to_get: Vec<EndpointID> = Vec::new();
                //case 1: this is a reply to an announce we sent, so we should update our ping
                //timings for that neighbor, insert the paths, and be done.
                if let Some(ANNOUNCE(time)) = waiting_replies.lock().await.remove(&(nonce,node_index)) {
                    let mut queue = announce_queue.lock().await; 
                    let mut table = neighbors.write().await;
                    table.update_ping(node_index,time.elapsed().as_millis() as u32); //truncate to 32 bits, since a ping of 49 days is unreasonable
                    for path in payload[1..].chunks_exact(39) {
                        let this_hop_ctr = path[0];
                        let this_path_len = u16::from_le_bytes([path[1],path[2]]);
                        let this_endpoint = EndpointID::decode(path[3..]).unwrap(); //should never panic since we are guaranteed 39 bytes in each path
                        if neighbors.
                        table.add_path(&mut queue, node_index, this_hop_ctr, this_path_len, this_endpoint, &mut this_rng);
                    }
                } else {
	                //case 2: this is a new 
	                //we need to insert the newly announced paths, and then send our own back
	                //this requires locking both the queue and routing table
	                //no problemo though
	                let size_filled_maybe = {
	                    let mut queue = announce_queue.lock().await; 
	                    let mut table = neighbors.write().await;
	                    for path in payload[1..].chunks_exact(39) {
	                        let this_hop_ctr = path[0];
	                        let this_path_len = u16::from_le_bytes([path[1],path[2]]);
	                        let this_endpoint = EndpointID::decode(path[3..]).unwrap(); //should never panic since we are guaranteed 39 bytes in each path
	                        table.add_path(&mut queue, node_index, this_hop_ctr, this_path_len, this_endpoint, &mut this_rng);
	                    }
	                    queue.get_chunk(&mut response_buf[39..], 31); //fill up as many as we can, that is, 31
	                };
	                if let Ok(size_filled) = size_filled_maybe {
	                    response_buf[38] = size_filled as u8;
	                    fill_message_header(&mut response_buf, MessageType::ANNOUNCE, size_filled + 1, &mut this_rng);
	                } else {
	                    response_buf[38] = 0;
                        fill_message_header(&mut response_buf, MessageType::ANNOUNCE, 1, &mut this_rng);
	                }
                    encrypt_and_send(&mut response_buf, *response_nonce, node.current_key, node.IP).await;
                }
                //now that we are done with the ping, we see if we have any of those in our
                //seeking-queue
            },
            MessageType::SEEK => {
                //case 1: the set of sought endpoints intersects with our announce-queue
                let mut endpoints_to_announce: Vec<EndpointID> = Vec::new();
                for endpoint in payload[1..].chunks_exact(39) {
                    let this_endpoint = EndpointID::decode(path[3..]).unwrap();
                    let table = neighbors.read().await;
                    let endpoint_manager = endpoints_to_serve.read().await;
                    if table.contains_path(this_endpoint) || endpoint_manager.contains(this_endpoint) {
                        endpoints_to_announce.push(this_endpoint);
                    }
                }
                if !endpoints_to_announce.is_empty() {
                    let table = neighbors.read().await;
                    for (i,endpoint) in endpoints_to_announce.iter().enumerate() {
                        if let Some((path_len,path_hops)) = table.get_path_info(endpoint) && i < 31 {
                            response_buf[39+(i*39)] = path_hops;
                            response_buf[(40+(i*39))..(42+(i*39))].copy_from_slice(&path_len.to_le_bytes());
                            endpoint.encode(response_buf[(42+(i*39))..(78+(i*39))]);
                        }
                    }
                    //fill the rest with random endpoints to announce

                }
            }

        }
    }
}

