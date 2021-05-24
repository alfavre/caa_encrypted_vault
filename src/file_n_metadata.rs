use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedFile {
    pub encrypted_name: String, // might be replaced by a hash of decrpted file name instead
    pub encrypted_data: String,
    pub file_salt: String,
    pub file_nonce: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MetaData {
    pub unique_id: u64,
    pub encrypted_filenames: Vec<String>,
    pub user_salt: String,
    pub user_nonce: String,
    pub shared_secret: String,
}