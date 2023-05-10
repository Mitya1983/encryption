#include "encryption.hpp"

#include <filters.h>
#include <base64.h>
#include <eax.h>
#include <aes.h>

auto tristan::encryption::encodeBase64(const std::string& raw_string) -> std::string {
    std::string encoded;
    CryptoPP::StringSource ss(raw_string, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
    return encoded;
}

auto tristan::encryption::encodeBase64(const std::vector< unsigned char >& raw_vector) -> std::vector< uint8_t > {
    std::vector< unsigned char > encoded;
    CryptoPP::VectorSource ss(raw_vector, true, new CryptoPP::Base64Encoder(new CryptoPP::VectorSink (encoded), false));
    auto end = std::find(encoded.begin(), encoded.end(), 0);
    encoded.erase(end, encoded.end());
    return encoded;
}

auto tristan::encryption::decodeBase64(const std::string& encoded_string) -> std::string {
    std::string decoded;
    CryptoPP::StringSource ss(encoded_string, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
    return decoded;
}

auto tristan::encryption::decodeBase64(const std::vector< unsigned char >& encoded_vector) -> std::vector< uint8_t > {
    std::vector< unsigned char > decoded;
    CryptoPP::VectorSource ss(encoded_vector, true, new CryptoPP::Base64Decoder(new CryptoPP::VectorSink(decoded)));
    auto end = std::find(decoded.begin(), decoded.end(), 0);
    decoded.erase(end, decoded.end());
    return decoded;
}

auto tristan::encryption::encryptAES(const std::string& raw_string, const std::array< uint8_t, 16 >& key, const std::array< uint8_t, 16 >& init_vector)
    -> std::string {
    CryptoPP::EAX< CryptoPP::AES >::Encryption encryptor;
    encryptor.SetKeyWithIV(key.data(), key.size(), init_vector.data(), init_vector.size());
    std::string encrypted;
    CryptoPP::StringSource ss(raw_string, true, new CryptoPP::AuthenticatedEncryptionFilter(encryptor, new CryptoPP::StringSink(encrypted)));
    return encrypted;
}

auto tristan::encryption::encryptAES(const std::string& raw_string, const std::array< uint8_t, 32 >& key, const std::array< uint8_t, 16 >& init_vector)
    -> std::string {
    CryptoPP::EAX< CryptoPP::AES >::Encryption encryptor;
    encryptor.SetKeyWithIV(key.data(), key.size(), init_vector.data(), init_vector.size());
    std::string encrypted;
    CryptoPP::StringSource ss(raw_string, true, new CryptoPP::AuthenticatedEncryptionFilter(encryptor, new CryptoPP::StringSink(encrypted)));
    return encrypted;
}

auto tristan::encryption::encryptAES(const std::vector< unsigned char >& raw_vector,
                                     const std::array< uint8_t, 16 >& key,
                                     const std::array< uint8_t, 16 >& init_vector) -> std::vector< uint8_t > {
    CryptoPP::EAX< CryptoPP::AES >::Encryption encryptor;
    encryptor.SetKeyWithIV(key.data(), key.size(), init_vector.data(), init_vector.size());
    std::vector< uint8_t > encrypted;
    CryptoPP::VectorSource ss(raw_vector, true, new CryptoPP::AuthenticatedEncryptionFilter(encryptor, new CryptoPP::VectorSink(encrypted)));

    return encrypted;
}

auto tristan::encryption::encryptAES(const std::vector< unsigned char >& raw_vector,
                                     const std::array< uint8_t, 32 >& key,
                                     const std::array< uint8_t, 16 >& init_vector) -> std::vector< uint8_t > {
    CryptoPP::EAX< CryptoPP::AES >::Encryption encryptor;
    encryptor.SetKeyWithIV(key.data(), key.size(), init_vector.data(), init_vector.size());
    std::vector< uint8_t > encrypted;
    CryptoPP::VectorSource ss(raw_vector, true, new CryptoPP::AuthenticatedEncryptionFilter(encryptor, new CryptoPP::VectorSink(encrypted)));

    return encrypted;
}

auto tristan::encryption::decryptAES(const std::string& aes_encrypted_string,
                                     const std::array< uint8_t , 16 >& key,
                                     const std::array< uint8_t, 16 >& init_vector) -> std::string {
    CryptoPP::EAX< CryptoPP::AES >::Decryption decrypter;
    decrypter.SetKeyWithIV(key.data(), key.size(), init_vector.data(), init_vector.size());
    std::string decrypted;
    CryptoPP::StringSource ss(aes_encrypted_string, true, new CryptoPP::AuthenticatedDecryptionFilter(decrypter, new CryptoPP::StringSink(decrypted)));

    return decrypted;
}

auto tristan::encryption::decryptAES(const std::string& aes_encrypted_string,
                                     const std::array< uint8_t, 32 >& key,
                                     const std::array< uint8_t, 16 >& init_vector) -> std::string {
    CryptoPP::EAX< CryptoPP::AES >::Decryption decrypter;
    decrypter.SetKeyWithIV(key.data(), key.size(), init_vector.data(), init_vector.size());
    std::string decrypted;
    CryptoPP::StringSource ss(aes_encrypted_string, true, new CryptoPP::AuthenticatedDecryptionFilter(decrypter, new CryptoPP::StringSink(decrypted)));

    return decrypted;
}

auto tristan::encryption::decryptAES(const std::vector< unsigned char >& aes_encrypted_vector,
                                     const std::array< uint8_t, 16 >& key,
                                     const std::array< uint8_t, 16 >& init_vector) -> std::vector< uint8_t > {
    CryptoPP::EAX< CryptoPP::AES >::Decryption decrypter;
    decrypter.SetKeyWithIV(key.data(), key.size(), init_vector.data(), init_vector.size());
    std::vector< unsigned char > decrypted;
    CryptoPP::VectorSource ss(aes_encrypted_vector, true, new CryptoPP::AuthenticatedDecryptionFilter(decrypter, new CryptoPP::VectorSink(decrypted)));
    auto end = std::find(decrypted.begin(), decrypted.end(), 0);
    decrypted.erase(end, decrypted.end());
    return decrypted;
}

auto tristan::encryption::decryptAES(const std::vector< unsigned char >& aes_encrypted_vector,
                                     const std::array< uint8_t, 32 >& key,
                                     const std::array< uint8_t, 16 >& init_vector) -> std::vector< uint8_t > {
    CryptoPP::EAX< CryptoPP::AES >::Decryption decrypter;
    decrypter.SetKeyWithIV(key.data(), key.size(), init_vector.data(), init_vector.size());

    std::vector< unsigned char > decrypted;
    CryptoPP::VectorSource ss(aes_encrypted_vector, true, new CryptoPP::AuthenticatedDecryptionFilter(decrypter, new CryptoPP::VectorSink(decrypted)));
    auto end = std::find(decrypted.begin(), decrypted.end(), 0);
    decrypted.erase(end, decrypted.end());
    return decrypted;
}
