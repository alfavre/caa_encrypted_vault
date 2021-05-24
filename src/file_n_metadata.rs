use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedFile {
    pub pt_filename_hash: String,
    pub encrypted_data: String,
    pub file_salt: String,
    pub file_nonce: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MetaData {
    pub encrypted_filenames: Vec<String>,
    pub user_salt: String,
    pub user_nonce: String,
    pub shared_secret: String,
}

impl MetaData {
    pub fn empty() -> MetaData {
        MetaData {
            encrypted_filenames: Vec::new(),
            user_salt: String::new(),
            user_nonce: String::new(),
            shared_secret: String::new(),
        }
    }
}
