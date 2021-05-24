use super::*;
use read_input::prelude::*;
use server::Server;

pub fn hello_world() -> () {
    println!("hello world client edition")
}

pub struct Client {
    master_password: String,
    user_id: u64,
}

impl Client {
    fn new(master_password: String, user_id: u64) -> Client {
        Client {
            master_password: master_password,
            user_id: user_id,
        }
    }

    pub fn entrypoint(server: Server) -> () {
        let user_id: u64 = input().msg("Please enter your unique id.\nId: ").get();
        let master_password: String = input().msg("Please enter you password.\nPassword: ").get();
        let client = Client::new(master_password, user_id);

        println!("We will now connect to server. Please wait a moment.");

        let connected_server = Server::connection();
    }
}
