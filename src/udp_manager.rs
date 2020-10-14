//NOTE: this is no longer up to date! Keeping it though because some of the code may be useful in
//the future
//this file contains code which manages all state for SPDB events.
//also contains the udp_listen, which is the loop handling incoming UDP traffic
//UDP messages are all handled synchronously, since there is no significant computation involved in
//any of them
use net_types::{EndpointID,Node,RoutingTable, MessageType, PathQueue, SeekData, ReplyData, GetData};
use rand_core::RngCore;
use rand_isaac::isaac::Isaac64Rng;
use getrandom::getrandom;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use x25519_dalek::{EphemeralSecret,PublicKey};
use std::collections::{HashMap, HashMap};
use tokio::sync::{Mutex,RwLock}


async fn udp_listen(listen_address: SocketAddr, announce_queue: Arc<Mutex<PathQueue>>, seeking_set: Arc<RwLock<HashMap<EndpointId,SeekData>>>, waiting_replies: Arc<Mutex<HashMap<([u8;16],u16),ReplyData>>>, neighbors: Arc<RwLock<RoutingTable>>, endpoints_to_serve: Arc<RwLock<EndpointManager>>, mem_limit: usize) -> Result<()> {
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
        let mut response_nonce = decrypted_buf[0..16] as &[u8;16];
        let msg_type = MessageType(decrypted_buf[16]);
        let msg_flags = decrypted_buf[17] as usize;
        let msg_len = u32::from_le_bytes([decrypted_buf[18],decrypted_buf[19],decrypted_buf[20],decrypted_buf[21]]);
        let payload = decrypted_buf[22..(22+(msg_len as usize))];
        let mut response_buf: [u8;1272] = [0;1272]; //stores the response. We build everything in-place to avoid allocations
        match msg_type {
            MessageType::ANNOUNCE => {
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
                        table.add_path(&mut queue, node_index, this_hop_ctr, this_path_len, this_endpoint, &mut this_rng);
                    }
                } else {
	                //case 2: this is a new ping
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
	                    queue.get_chunk(&mut response_buf[39..], 31) //fill up as many as we can, that is, 31
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
                //now that we are done with the ping, we see if we are seeking any of the nodes we
                //just heard about.
                for path in payload[1..].chunks_exact(39) {
                    let this_endpoint = EndpointID::decode(path);
                    //case: we happen to be personally seeking this endpoint
                    if let Some(data) = seeking_set.read().await.get(this_endpoint) {
                        //construct the GET request
                        let mut this_get_data = GetData { endpoint: this_endpoint, my_secret_key: None, my_symmetric_key: None };
                        //generate a new nonce
                        this_rng.fill_bytes(response_nonce);
                        response_buf[38..72].copy_from_slice(path);
                        if data.use_direct {
                            response_buf[72..90].copy_from_slice(encode_ip(&addr));
                            this_get_data.my_symmetric_key = Some([0;32]);
                            this_rng.fill_bytes(&mut this_get_data.my_symmetric_key.unwrap());
                            response_buf[90..106].copy_from_slice(response_nonce);
                            response_buf[106..138].copy_from_slice(&this_get_data.my_symmetric_key.unwrap());
                        } else {
                            response[72..138].fill(0u8);
                        }
                        let mut cursor:usize = 140;
                        if this_endpoint.is_dynamic {
                            response_buf[138] = 1;
                            response_buf[139] = 0;
                            if let Some(key) = data.use_special_key {
                                let pubkey = PublicKey::from(&key);
                                response_buf[140..172].copy_from_slice(pubkey.as_bytes());
                                this_get_data.my_secret_key = Some(key);
                            } else {
                                let new_seckey = EphemeralSecret::new(&mut this_rng);
                                let new_pubkey = PublicKey::from(&new_seckey);
                                response_buf[140..172].copy_from_slice(new_pubkey.as_bytes());
                                this_get_data.my_secret_key = Some(new_seckey);
                            }
                            cursor = 172;
                        } else {
                            response_buf[138] = 0; 
                            response_buf[139] = 0; 
                        }
                        if let Some(additional_data) = data.additional_data {
                            response_buf[additional_data_start..].copy_from_slice(&additional_data);
                            cursor = cursor + additional_data.len();
                        }
                        fill_message_header(&mut response_buf, MessageType::GET, cursor, &mut this_rng);
                        encrypt_and_send(&mut response_buf, *response_nonce, node.current_key, node.IP).await;
                    } //done!
                }
            },
            MessageType::SEEK => {
                //get a list of the sought endpoints in our announce queue
                let mut endpoints_to_announce: Vec<EndpointID> = Vec::new();
                let mut endpoints_to_seek: Vec<(EndpointID,u8,u16)> = Vec::new();
                for path in payload[1..].chunks_exact(39) {
                    let this_endpoint = EndpointID::decode(path[3..]).unwrap();
                    let table = neighbors.read().await;
                    let endpoint_manager = endpoints_to_serve.read().await;
                    if table.contains_path(this_endpoint) || endpoint_manager.contains(this_endpoint) {
                        endpoints_to_announce.push(this_endpoint);
                    } else {
                        endpoints_to_seek.push((this_endpoint,u16::from_le_bytes([path[0], path[1]]),path[2]));
                    }
                }
                if !endpoints_to_announce.is_empty() {
                    let table = neighbors.read().await;
                    for (i,endpoint) in endpoints_to_announce.iter().enumerate().take(31) {
                        if let Some((path_len,path_hops)) = table.get_path_info(endpoint) {
                            response_buf[39+(i*39)] = path_hops;
                            response_buf[(40+(i*39))..(42+(i*39))].copy_from_slice(&path_len.to_le_bytes());
                            endpoint.encode(&mut response_buf[(42+(i*39))..(78+(i*39))]);
                        }
                    }
                    let mut size_filled: Result<usize> = Ok(40 + endpoints_to_announce.len()*39);
                    //fill the rest with random endpoints to announce
                    if endpoints_to_announce.len() < 31 {
                        let start = 40+endpoints_to_announce.len()*39;
                        let num = (1280 - start)/39;
                        size_filled = announce_queue.lock().await.get_chunk(&mut response_buf[start..], num).and_then(move |a| { a + start });
                    }
                    this_rng.fill_bytes(&mut response_nonce);
                    if let Ok(filled) = size_filled {
                        fill_message_header(&mut response_buf, MessageType::SEEK, filled, &mut this_rng);
                    } else {
                        fill_message_header(&mut response_buf, MessageType::SEEK, 40 + endpoints_to_announce.len()*39, &mut this_rng);
                    }
                    waiting_replies.lock().await.insert((response_nonce,node_index),ReplyData::ANNOUNCE(Instant::now()));
                    encrypt_and_send(&mut response_buf, *response_nonce, node.current_key, node.IP).await;
                }
                //add the list of endpoints which we are not announcing to the seeking-queue
                let queue = seeking_queue.lock().await;
                ///TODO
            }
        }
    }
}

