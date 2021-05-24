mod client;
mod constant;
mod file_n_metadata;
mod server;
mod vault;

use sodiumoxide::crypto::*;

fn main() {
    println!("Hello, world!");
    client::hello_world();
    server::hello_world();

    vault::Vault::create_default_db();
}
