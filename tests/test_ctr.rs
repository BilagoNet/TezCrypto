use tezcrypto::{ctr256_encrypt, ctr256_decrypt};
use hex::decode;

#[test]
fn test_ctr256_encrypt() {
    let key = decode("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4").unwrap();
    let iv = decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF").unwrap();
    let plaintext = decode("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710").unwrap();
    let ciphertext = decode("601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C52B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6").unwrap();

    let result = ctr256_encrypt(&plaintext, &key, &iv, 0);
    assert_eq!(result, ciphertext);
}

#[test]
fn test_ctr256_decrypt() {
    let key = decode("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4").unwrap();
    let iv = decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF").unwrap();
    let ciphertext = decode("601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C52B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6").unwrap();
    let plaintext = decode("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710").unwrap();

    let result = ctr256_decrypt(&ciphertext, &key, &iv, 0);
    assert_eq!(result, plaintext);
}

#[test]
fn test_ctr256_encrypt_extra1() {
    let key = decode("776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104").unwrap();
    let iv = decode("00000060DB5672C97AA8F0B200000001").unwrap();
    let plaintext = decode("53696E676C6520626C6F636B206D7367").unwrap();
    let ciphertext = decode("145AD01DBF824EC7560863DC71E3E0C0").unwrap();

    let result = ctr256_encrypt(&plaintext, &key, &iv, 0);
    assert_eq!(result, ciphertext);
}

#[test]
fn test_ctr256_encrypt_extra2() {
    let key = decode("F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884").unwrap();
    let iv = decode("00FAAC24C1585EF15A43D87500000001").unwrap();
    let plaintext = decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").unwrap();
    let ciphertext = decode("F05E231B3894612C49EE000B804EB2A9B8306B508F839D6A5530831D9344AF1C").unwrap();

    let result = ctr256_encrypt(&plaintext, &key, &iv, 0);
    assert_eq!(result, ciphertext);
}
