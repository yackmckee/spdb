# SpeeDyBase
## A protocol and rust implementation for a light fast peer to peer database

This repository contains a description of the SPDB protocol, and a performant Rust implementation with a network API.

## Building

Clone the repository and run `cargo build --release`. The built binary will be in `target/release/speediboi`.

## Running

Run `target/release/speediboi --help` for a list of options and their defaults.
A sample config file is provided in `config.toml`

## Development

The implementation is built to be fully asynchronous and to respect configured limits on network and memory whenever possible.
Development is split into five main files:

- main.rs defines top-level control flow
- config.rs provides configuration parsing
- api.rs handles API requests.
- network.rs handles routing and the Kademlia network
- store.rs handles the block database
- protocol.rs performs most of the Speediboi protocol logic
- serialize.rs handles serialization/deserialization of data types.
