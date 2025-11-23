use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;

pub fn ctr256_encrypt(data: &[u8], key: &[u8], iv: &[u8], state: u8) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let key = GenericArray::from_slice(key);
    let cipher = Aes256::new(key);
    
    let mut curr_iv = [0u8; 16];
    curr_iv.copy_from_slice(iv);
    
    let mut state = state as usize;
    let mut chunk = GenericArray::from(curr_iv);
    
    // Generate initial keystream block
    cipher.encrypt_block(&mut chunk); // Encrypt IV to get keystream

    let mut i = 0;
    while i < data.len() {
        let len = std::cmp::min(data.len() - i, 16 - state);
        
        for j in 0..len {
            out[i + j] = data[i + j] ^ chunk[state + j];
        }
        
        i += len;
        state += len;
        
        if state >= 16 {
            state = 0;
            // Increment IV (Big Endian)
            for k in (0..16).rev() {
                curr_iv[k] = curr_iv[k].wrapping_add(1);
                if curr_iv[k] != 0 {
                    break;
                }
            }
            
            chunk = GenericArray::from(curr_iv);
            cipher.encrypt_block(&mut chunk);
        }
    }

    out
}

pub fn ctr256_decrypt(data: &[u8], key: &[u8], iv: &[u8], state: u8) -> Vec<u8> {
    ctr256_encrypt(data, key, iv, state)
}
