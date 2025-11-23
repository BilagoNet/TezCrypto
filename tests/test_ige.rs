use tezcrypto::{ige256_encrypt, ige256_decrypt};
use rand::Rng;

#[test]
fn test_ige256_random() {
    let mut rng = rand::rng();
    
    for _ in 0..500 {
        let len = rng.random_range(1..=64) * 16;
        let mut data = vec![0u8; len];
        rng.fill(&mut data[..]);
        
        let mut key = [0u8; 32];
        rng.fill(&mut key[..]);
        
        let mut iv = [0u8; 32];
        rng.fill(&mut iv[..]);
        
        let encrypted = ige256_encrypt(&data, &key, &iv);
        let decrypted = ige256_decrypt(&encrypted, &key, &iv);
        
        assert_eq!(data, decrypted);
    }
}
