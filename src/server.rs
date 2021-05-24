use super::*;

pub fn hello_world() -> () {
    println!("hello world server edition")
}

pub struct Server {}

impl Server {
    fn new(encrypted_file_vault_path: &str, metadata_vault_path: &str) -> Server {
        Server {}
    }

    pub fn connection() -> Server {
        Server::new(
            constant::VAULT_ENCRYPTED_FILE_PATH,
            constant::VAULT_METADATA_PATH,
        )
    }

    pub fn send_challenge(&mut self) -> () {
        let key = auth::gen_key();
        let data_to_authenticate = b"some data";
        let tag = auth::authenticate(data_to_authenticate, &key);
        assert!(auth::verify(&tag, data_to_authenticate, &key));
    }
}
