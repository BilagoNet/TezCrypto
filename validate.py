import tezcrypto
import os


def test_cbc():
    key = bytes.fromhex(
        "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4"
    )
    iv = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    plaintext = bytes.fromhex(
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51"
        "30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710"
    )
    ciphertext = bytes.fromhex(
        "F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D"
        "39F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B"
    )

    assert tezcrypto.cbc256_encrypt(plaintext, key, iv) == ciphertext
    assert tezcrypto.cbc256_decrypt(ciphertext, key, iv) == plaintext
    print("CBC tests passed")


def test_ctr():
    key = bytes.fromhex(
        "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4"
    )
    iv = bytes.fromhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")
    plaintext = bytes.fromhex(
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51"
        "30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710"
    )
    ciphertext = bytes.fromhex(
        "601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C5"
        "2B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6"
    )

    assert tezcrypto.ctr256_encrypt(plaintext, key, iv, bytes(1)) == ciphertext
    assert tezcrypto.ctr256_decrypt(ciphertext, key, iv, bytes(1)) == plaintext
    print("CTR tests passed")


def test_ige():
    key = os.urandom(32)
    iv = os.urandom(32)
    data = os.urandom(16 * 10)

    encrypted = tezcrypto.ige256_encrypt(data, key, iv)
    decrypted = tezcrypto.ige256_decrypt(encrypted, key, iv)

    assert decrypted == data
    print("IGE tests passed")


if __name__ == "__main__":
    test_cbc()
    test_ctr()
    test_ige()
    print("All tests passed!")
