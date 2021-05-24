use super::*;
use file_n_metadata::{EncryptedFile, MetaData};
use sodiumoxide::base64::*;
use sodiumoxide::crypto::{pwhash, secretbox};
use sodiumoxide::crypto::pwhash::HashedPassword;
use std::fs::File;
use std::io::{BufRead, BufReader, Error, Write};

///this should control all access to db
#[derive(Debug)]
pub struct Vault {
    metadata_table_path: String,
    encrypted_file_table_path: String,
    metadata_vec: Vec<MetaData>,
    encrypted_files_vec: Vec<EncryptedFile>,
}

impl Vault {
    fn new(path_metadata_vault: &str, path_enc_file_vault: &str) -> Vault {
        Vault {
            metadata_table_path: String::from(path_metadata_vault),
            encrypted_file_table_path: String::from(path_enc_file_vault),
            metadata_vec: Vault::retrieve_all_metadata(path_metadata_vault),
            encrypted_files_vec: Vault::retrieve_all_encrypted_file(path_enc_file_vault),
        }
    }

    /// static method
    fn retrieve_all_metadata(path: &str) -> Vec<MetaData> {
        let mut my_metadata_vec = Vec::new();

        match File::open(path) {
            Ok(input) => {
                let buffered = BufReader::new(input);
                for line in buffered.lines() {
                    my_metadata_vec.push(serde_json::from_str(line.unwrap().as_str()).unwrap());
                }
            }
            Err(_) => (), //do nothing if failed to open file
        }
        my_metadata_vec
    }

    /// static method
    fn retrieve_all_encrypted_file(path: &str) -> Vec<EncryptedFile> {
        let mut my_enc_file_vec = Vec::new();

        match File::open(path) {
            Ok(input) => {
                let buffered = BufReader::new(input);
                for line in buffered.lines() {
                    my_enc_file_vec.push(serde_json::from_str(line.unwrap().as_str()).unwrap());
                }
            }
            Err(_) => (), //do nothing if failed to open file
        }
        my_enc_file_vec
    }

    fn store_all_metadata(&self) -> () {
        let mut metadata_json = String::from("");
        let mut output = File::create(&self.metadata_table_path).unwrap(); // I'm okay with a panic here

        for metadata in &self.metadata_vec {
            // no need for copy as I just write the values
            metadata_json.push_str(&serde_json::to_string(&metadata).unwrap());
            metadata_json.push_str("\n");
        }

        write!(output, "{}", metadata_json); // I'm okay with a panic here
    }

    fn store_all_encrypted_file(&self) -> () {
        let mut encrypted_file_json = String::from("");
        let mut output = File::create(&self.encrypted_file_table_path).unwrap(); // I'm okay with a panic here

        for encrypted_file in &self.encrypted_files_vec {
            // no need for copy as I just write the values
            encrypted_file_json.push_str(&serde_json::to_string(&encrypted_file).unwrap());
            encrypted_file_json.push_str("\n");
        }

        write!(output, "{}", encrypted_file_json); // I'm okay with a panic here
    }

    pub fn slice_to_string(slice: &[u8]) -> String {
        String::from(std::str::from_utf8(&slice).unwrap())
    }

    pub fn string_to_slice(string: &str) -> &[u8] {
        // might cause lifetime problems
        string.as_bytes()
    }

    pub fn vec_to_string(vec: Vec<u8>) -> String {
        String::from_utf8(vec).unwrap()
    }

    pub fn vec_to_slice<'a>(vec: Vec<u8>) -> () {
        // might cause lifetime problems
        println!("dont call this method");
        // &vec
    }

    fn store_all(&self) -> () {
        self.store_all_encrypted_file();
        self.store_all_metadata();
    }

    pub fn create_default_db() -> () {
        //init
        let mut my_vault = Vault::new(
            constant::VAULT_METADATA_PATH,
            constant::VAULT_ENCRYPTED_FILE_PATH,
        );

        let mut my_metadata_vec: Vec<MetaData> = Vec::new();
        let mut my_enc_file_vec: Vec<EncryptedFile> = Vec::new();

        //create the salt for the user
        let my_user_salt = pwhash::gen_salt();

        // derive the first key from pass and hash
        let mut mk = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_master_key) = mk;
        pwhash::derive_key(
            my_master_key,
            constant::TEST_STRONG_PASS.as_bytes(), // we derive master pass here
            &my_user_salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();

        // making xsalsa key from master key
        let my_key_xsalsa = secretbox::xsalsa20poly1305::Key::from_slice(my_master_key).unwrap();

        // making a nonce for the master key
        let my_nonce = secretbox::gen_nonce();

        // we encrypt filenames
        let my_test_name_bytes: &[u8] = constant::TEST_NAME_TO_ENCRYPT.as_bytes(); // those weird casts are a sight to behold
        let my_test_name_encrypted = secretbox::seal(my_test_name_bytes, &my_nonce, &my_key_xsalsa); // need to be encoded b64 if I want a string, utf8 doesnt work
        let my_test_name_bytes2: &[u8] = constant::TEST_NAME_TO_ENCRYPT_2.as_bytes(); // those weird casts are a sight to behold
        let my_test_name_encrypted2 =
            secretbox::seal(my_test_name_bytes2, &my_nonce, &my_key_xsalsa); // need to be encoded b64 if I want a string, utf8 doesnt work
        let my_test_name_bytes3: &[u8] = constant::TEST_NAME_TO_ENCRYPT_3.as_bytes(); // those weird casts are a sight to behold
        let my_test_name_encrypted3 =
            secretbox::seal(my_test_name_bytes3, &my_nonce, &my_key_xsalsa); // need to be encoded b64 if I want a string, utf8 doesnt work
        let my_test_name_bytes4: &[u8] = constant::TEST_NAME_TO_ENCRYPT_4.as_bytes(); // those weird casts are a sight to behold
        let my_test_name_encrypted4 =
            secretbox::seal(my_test_name_bytes4, &my_nonce, &my_key_xsalsa); // need to be encoded b64 if I want a string, utf8 doesnt work

        // we store our encrypted file name
        let mut my_encrypted_filenames: Vec<String> = Vec::new();
        my_encrypted_filenames.push(encode(my_test_name_encrypted.clone(), Variant::UrlSafe)); // clone because i fu
        my_encrypted_filenames.push(encode(my_test_name_encrypted2.clone(), Variant::UrlSafe));
        my_encrypted_filenames.push(encode(my_test_name_encrypted3.clone(), Variant::UrlSafe));
        my_encrypted_filenames.push(encode(my_test_name_encrypted4.clone(), Variant::UrlSafe));

        // we fill our struct for db
        let my_metadata = MetaData {
            unique_id: 0,
            encrypted_filenames: my_encrypted_filenames,
            shared_secret: String::from("None"),
            user_salt: encode(my_user_salt, Variant::UrlSafe),
            user_nonce: encode(my_nonce, Variant::UrlSafe),
        };

        // we will now encrypt the data of each file

        //we need a salt for each file
        let my_file_salt1 = pwhash::gen_salt();
        let my_file_salt2 = pwhash::gen_salt();
        let my_file_salt3 = pwhash::gen_salt();
        let my_file_salt4 = pwhash::gen_salt();

        //we need a key for each file
        let mut k1 = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_file_key_1) = k1;
        pwhash::derive_key(
            my_file_key_1,
            constant::TEST_STRONG_PASS.as_bytes(), // we derive master pass here
            &my_file_salt1,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();

        let mut k2 = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_file_key_2) = k2;
        pwhash::derive_key(
            my_file_key_2,
            constant::TEST_STRONG_PASS.as_bytes(), // we derive master pass here
            &my_file_salt2,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();

        let mut k3 = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_file_key_3) = k3;
        pwhash::derive_key(
            my_file_key_3,
            constant::TEST_STRONG_PASS.as_bytes(), // we derive master pass here
            &my_file_salt3,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();

        let mut k4 = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_file_key_4) = k4;
        pwhash::derive_key(
            my_file_key_4,
            constant::TEST_STRONG_PASS.as_bytes(), // we derive master pass here
            &my_file_salt4,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();

        //we need a nonce for each file
        let my_file_nonce_1 = secretbox::gen_nonce();
        let my_file_nonce_2 = secretbox::gen_nonce();
        let my_file_nonce_3 = secretbox::gen_nonce();
        let my_file_nonce_4 = secretbox::gen_nonce();

        // we need a xsalsa key for each file
        let my_file_key_xsalsa_1 =
            secretbox::xsalsa20poly1305::Key::from_slice(my_file_key_1).unwrap();
        let my_file_key_xsalsa_2 =
            secretbox::xsalsa20poly1305::Key::from_slice(my_file_key_2).unwrap();
        let my_file_key_xsalsa_3 =
            secretbox::xsalsa20poly1305::Key::from_slice(my_file_key_3).unwrap();
        let my_file_key_xsalsa_4 =
            secretbox::xsalsa20poly1305::Key::from_slice(my_file_key_4).unwrap();

        // we encrypt the file data
        let my_test_file_bytes_1: &[u8] = constant::TEST_DATA_TO_ENCRYPT.as_bytes(); // those weird casts are a sight to behold
        let my_test_file_encrypted_1 = secretbox::seal(
            my_test_file_bytes_1,
            &my_file_nonce_1,
            &my_file_key_xsalsa_1,
        );

        let my_test_file_bytes_2: &[u8] = constant::TEST_DATA_TO_ENCRYPT_2.as_bytes(); // those weird casts are a sight to behold
        let my_test_file_encrypted_2 = secretbox::seal(
            my_test_file_bytes_2,
            &my_file_nonce_2,
            &my_file_key_xsalsa_2,
        );

        let my_test_file_bytes_3: &[u8] = constant::TEST_DATA_TO_ENCRYPT_3.as_bytes(); // those weird casts are a sight to behold
        let my_test_file_encrypted_3 = secretbox::seal(
            my_test_file_bytes_3,
            &my_file_nonce_3,
            &my_file_key_xsalsa_3,
        );

        let my_test_file_bytes_4: &[u8] = constant::TEST_DATA_TO_ENCRYPT_4.as_bytes(); // those weird casts are a sight to behold
        let my_test_file_encrypted_4 = secretbox::seal(
            my_test_file_bytes_4,
            &my_file_nonce_4,
            &my_file_key_xsalsa_4,
        );

        // we get a hash of the pt for each filename
        let pwh1 = pwhash::pwhash(
            constant::TEST_NAME_TO_ENCRYPT.as_bytes(),
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        let pwh_bytes1 = pwh1.as_ref();

        let pwh2 = pwhash::pwhash(
            constant::TEST_NAME_TO_ENCRYPT_2.as_bytes(),
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        let pwh_bytes2 = pwh2.as_ref();

        let pwh3 = pwhash::pwhash(
            constant::TEST_NAME_TO_ENCRYPT_3.as_bytes(),
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        let pwh_bytes3 = pwh3.as_ref();

        let pwh4 = pwhash::pwhash(
            constant::TEST_NAME_TO_ENCRYPT_4.as_bytes(),
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        let pwh_bytes4 = pwh4.as_ref();

        // we fill our structs
        let my_file_struct_1 = EncryptedFile {
            pt_filename_hash: encode(pwh_bytes1, Variant::UrlSafe), // this one has been encrypted with master key, not file key
            encrypted_data: encode(my_test_file_encrypted_1, Variant::UrlSafe),
            file_salt: encode(my_file_salt1, Variant::UrlSafe),
            file_nonce: encode(my_file_nonce_1, Variant::UrlSafe),
        };

        let my_file_struct_2 = EncryptedFile {
            pt_filename_hash: encode(pwh_bytes2, Variant::UrlSafe), // this one has been encrypted with master key, not file key
            encrypted_data: encode(my_test_file_encrypted_2, Variant::UrlSafe),
            file_salt: encode(my_file_salt2, Variant::UrlSafe),
            file_nonce: encode(my_file_nonce_2, Variant::UrlSafe),
        };

        let my_file_struct_3 = EncryptedFile {
            pt_filename_hash: encode(pwh_bytes3, Variant::UrlSafe), // this one has been encrypted with master key, not file key
            encrypted_data: encode(my_test_file_encrypted_3, Variant::UrlSafe),
            file_salt: encode(my_file_salt3, Variant::UrlSafe),
            file_nonce: encode(my_file_nonce_3, Variant::UrlSafe),
        };

        let my_file_struct_4 = EncryptedFile {
            pt_filename_hash: encode(pwh_bytes4, Variant::UrlSafe), // this one has been encrypted with master key, not file key
            encrypted_data: encode(my_test_file_encrypted_4, Variant::UrlSafe),
            file_salt: encode(my_file_salt4, Variant::UrlSafe),
            file_nonce: encode(my_file_nonce_4, Variant::UrlSafe),
        };

        // we push our structs in vault and write the db
        my_metadata_vec.push(my_metadata);
        my_enc_file_vec.push(my_file_struct_1);
        my_enc_file_vec.push(my_file_struct_2);
        my_enc_file_vec.push(my_file_struct_3);
        my_enc_file_vec.push(my_file_struct_4);

        my_vault.metadata_vec = my_metadata_vec;
        my_vault.encrypted_files_vec = my_enc_file_vec;
        my_vault.store_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_filenames() {
        let test_metadata_vec = Vault::retrieve_all_metadata(constant::VAULT_METADATA_PATH);

        // we have to find master key

        let my_user_hash_slice = decode(&test_metadata_vec[0].user_salt, Variant::UrlSafe).unwrap();
        let my_user_hash = pwhash::Salt::from_slice(&my_user_hash_slice).unwrap();

        let mut mk = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_master_key) = mk;
        pwhash::derive_key(
            my_master_key,
            constant::TEST_STRONG_PASS.as_bytes(), // we derive master pass here
            &my_user_hash,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();

        //we have to find xsalsa key
        let my_key_xsalsa = secretbox::xsalsa20poly1305::Key::from_slice(my_master_key).unwrap();

        //we have to retriev the nonce
        let my_nonce_slice = decode(&test_metadata_vec[0].user_nonce, Variant::UrlSafe).unwrap();
        let my_nonce = secretbox::xsalsa20poly1305::Nonce::from_slice(&my_nonce_slice).unwrap();

        // we decrypt to check if it works
        let mut my_deciphered_test_name_vec: Vec<String> = Vec::new();
        for enc_name in &test_metadata_vec[0].encrypted_filenames {
            let decoded_enc_name = decode(enc_name, Variant::UrlSafe).unwrap();
            let my_deciphered_test_name =
                secretbox::open(&decoded_enc_name, &my_nonce, &my_key_xsalsa).unwrap();
            my_deciphered_test_name_vec.push(Vault::vec_to_string(my_deciphered_test_name));
            
        }

        assert_eq!(
            my_deciphered_test_name_vec[0],
            constant::TEST_NAME_TO_ENCRYPT
        );
        assert_eq!(
            my_deciphered_test_name_vec[1],
            constant::TEST_NAME_TO_ENCRYPT_2
        );
        assert_eq!(
            my_deciphered_test_name_vec[2],
            constant::TEST_NAME_TO_ENCRYPT_3
        );
        assert_eq!(
            my_deciphered_test_name_vec[3],
            constant::TEST_NAME_TO_ENCRYPT_4
        );
    }

    #[test]
    fn verify_files() {
        let test_metadata_vec = Vault::retrieve_all_metadata(constant::VAULT_METADATA_PATH);
        let test_enc_file_vec =
            Vault::retrieve_all_encrypted_file(constant::VAULT_ENCRYPTED_FILE_PATH);

        // decrypting filenames is pointless :/

        // we have to find all files key

        let mut decrypted_data_vec: Vec<String> = Vec::new();
        let mut pt_hahs_vec = Vec::new();

        for file in test_enc_file_vec {
            let my_file_hash_slice = decode(file.file_salt, Variant::UrlSafe).unwrap();
            let my_file_hash = pwhash::Salt::from_slice(&my_file_hash_slice).unwrap();

            let mut k = secretbox::Key([0; secretbox::KEYBYTES]);
            let secretbox::Key(ref mut my_key) = k;
            pwhash::derive_key(
                my_key,
                constant::TEST_STRONG_PASS.as_bytes(), // we derive master pass here
                &my_file_hash,
                pwhash::OPSLIMIT_INTERACTIVE,
                pwhash::MEMLIMIT_INTERACTIVE,
            )
            .unwrap();

            //we have to find xsalsa key
            let my_key_xsalsa = secretbox::xsalsa20poly1305::Key::from_slice(my_key).unwrap();

            //we have to retriev the nonce
            let my_nonce_slice = decode(&file.file_nonce, Variant::UrlSafe).unwrap();
            let my_nonce = secretbox::xsalsa20poly1305::Nonce::from_slice(&my_nonce_slice).unwrap();

            let decoded_enc_data = decode(file.encrypted_data, Variant::UrlSafe).unwrap();
            let my_deciphered_data =
                secretbox::open(&decoded_enc_data, &my_nonce, &my_key_xsalsa).unwrap();
            decrypted_data_vec.push(Vault::vec_to_string(my_deciphered_data));
        
            let pt_hash_slice = decode(file.pt_filename_hash, Variant::UrlSafe).unwrap();
            pt_hahs_vec.push(HashedPassword::from_slice(&pt_hash_slice).unwrap());
        }

        assert!(pwhash::pwhash_verify(&pt_hahs_vec[0], constant::TEST_NAME_TO_ENCRYPT.as_bytes()));
        assert!(pwhash::pwhash_verify(&pt_hahs_vec[1], constant::TEST_NAME_TO_ENCRYPT_2.as_bytes()));
        assert!(pwhash::pwhash_verify(&pt_hahs_vec[2], constant::TEST_NAME_TO_ENCRYPT_3.as_bytes()));
        assert!(pwhash::pwhash_verify(&pt_hahs_vec[3], constant::TEST_NAME_TO_ENCRYPT_4.as_bytes()));


        assert_eq!(decrypted_data_vec[0], constant::TEST_DATA_TO_ENCRYPT);
        assert_eq!(decrypted_data_vec[1], constant::TEST_DATA_TO_ENCRYPT_2);
        assert_eq!(decrypted_data_vec[2], constant::TEST_DATA_TO_ENCRYPT_3);
        assert_eq!(decrypted_data_vec[3], constant::TEST_DATA_TO_ENCRYPT_4);
    }
}
