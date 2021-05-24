mod client;
mod constant;
mod file_n_metadata;
mod server;
mod vault;

use client::Client;
use sodiumoxide::crypto::*;

fn main() {
    //vault::Vault::create_default_db();
    Client::entrypoint();
}
