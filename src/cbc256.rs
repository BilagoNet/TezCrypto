use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;

pub fn cbc256_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let key = GenericArray::from_slice(key);
    let cipher = Aes256::new(key);
    
    let mut curr_iv = [0u8; 16];
    curr_iv.copy_from_slice(iv);

    for i in (0..data.len()).step_by(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[i..i+16]);

        for j in 0..16 {
            block[j] ^= curr_iv[j];
        }

        let mut encrypted_block = GenericArray::from(block);
        cipher.encrypt_block(&mut encrypted_block);
        
        out[i..i+16].copy_from_slice(encrypted_block.as_slice());
        curr_iv.copy_from_slice(encrypted_block.as_slice());
    }

    out
}

pub fn cbc256_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let key = GenericArray::from_slice(key);
    let cipher = Aes256::new(key);
    
    let mut curr_iv = [0u8; 16];
    curr_iv.copy_from_slice(iv);

    for i in (0..data.len()).step_by(16) {
        let mut block = *GenericArray::from_slice(&data[i..i+16]);
        let next_iv = block;

        cipher.decrypt_block(&mut block);

        for j in 0..16 {
            block[j] ^= curr_iv[j];
        }

        out[i..i+16].copy_from_slice(block.as_slice());
        curr_iv.copy_from_slice(next_iv.as_slice());
    }

    out
}
