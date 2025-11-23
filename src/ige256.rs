use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;

pub fn ige256_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let key = GenericArray::from_slice(key);
    let cipher = Aes256::new(key);

    let mut iv1 = [0u8; 16];
    let mut iv2 = [0u8; 16];
    iv1.copy_from_slice(&iv[0..16]);
    iv2.copy_from_slice(&iv[16..32]);

    let mut chunk = [0u8; 16];
    let mut buffer = [0u8; 16];
    let mut block = [0u8; 16];

    for i in (0..data.len()).step_by(16) {
        // IGE is block mode, data must be multiple of 16.
        // The C code checks this. We assume valid input or handle it.
        // C code: if (data.len % 16 != 0) error.
        // We will assume 16 byte blocks.
        
        chunk.copy_from_slice(&data[i..i+16]);

        for j in 0..16 {
            buffer[j] = chunk[j] ^ iv1[j];
        }

        let mut encrypted_block = GenericArray::from(buffer);
        cipher.encrypt_block(&mut encrypted_block);
        
        for j in 0..16 {
            block[j] = encrypted_block[j] ^ iv2[j];
        }
        
        out[i..i+16].copy_from_slice(&block);

        iv1.copy_from_slice(&block);
        iv2.copy_from_slice(&chunk);
    }

    out
}

pub fn ige256_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let key = GenericArray::from_slice(key);
    let cipher = Aes256::new(key);

    let mut iv1 = [0u8; 16];
    let mut iv2 = [0u8; 16];
    iv2.copy_from_slice(&iv[0..16]);
    iv1.copy_from_slice(&iv[16..32]);

    let mut chunk = [0u8; 16];
    let mut buffer = [0u8; 16];
    let mut block = [0u8; 16];

    for i in (0..data.len()).step_by(16) {
        chunk.copy_from_slice(&data[i..i+16]);

        for j in 0..16 {
            buffer[j] = chunk[j] ^ iv1[j];
        }

        let mut decrypted_block = GenericArray::from(buffer);
        cipher.decrypt_block(&mut decrypted_block);

        for j in 0..16 {
            block[j] = decrypted_block[j] ^ iv2[j];
        }

        out[i..i+16].copy_from_slice(&block);

        iv1.copy_from_slice(&block);
        iv2.copy_from_slice(&chunk);
    }

    out
}
