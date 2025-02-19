#include "encryption.hpp"

#include "filters.h"
#include "base64.h"
#include "eax.h"
#include "aes.h"

auto mt::encryption::encodeBase64(const std::string& p_string) -> std::string {
    std::string l_string;
    CryptoPP::StringSource l_string_source(p_string, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(l_string), false));
    return l_string;
}

auto mt::encryption::encodeBase64(const std::vector< uint8_t >& p_vector) -> std::vector< uint8_t > {
    std::vector< uint8_t > l_vector;
    CryptoPP::VectorSource l_vector_source(p_vector, true, new CryptoPP::Base64Encoder(new CryptoPP::VectorSink(l_vector), false));
    //    auto end = std::find(l_vector.begin(), l_vector.end(), 0);
    //    l_vector.erase(end, l_vector.end());
    return l_vector;
}

auto mt::encryption::decodeBase64(const std::string& p_string) -> std::string {
    std::string l_string;
    CryptoPP::StringSource l_string_source(p_string, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(l_string)));
    return l_string;
}

auto mt::encryption::decodeBase64(const std::vector< uint8_t >& p_vector) -> std::vector< uint8_t > {
    std::vector< uint8_t > l_vector;
    CryptoPP::VectorSource l_vector_source(p_vector, true, new CryptoPP::Base64Decoder(new CryptoPP::VectorSink(l_vector)));
    //    auto end = std::find(l_vector.begin(), l_vector.end(), 0);
    //    l_vector.erase(end, l_vector.end());
    return l_vector;
}

auto mt::encryption::encryptAES(const std::string& p_string, Key p_key, const std::array< uint8_t, 16 >& p_init_vector) -> std::string {
    CryptoPP::EAX< CryptoPP::AES >::Encryption l_encryption;
    std::visit(
        [&l_encryption, &p_init_vector](auto&& key) {
            l_encryption.SetKeyWithIV(key.data(), key.size(), p_init_vector.data(), p_init_vector.size());
        },
        p_key);
    std::string l_string;
    CryptoPP::StringSource ss(p_string, true, new CryptoPP::AuthenticatedEncryptionFilter(l_encryption, new CryptoPP::StringSink(l_string)));
    return l_string;
}

auto mt::encryption::encryptAES(const std::vector< uint8_t >& p_raw_vector, Key p_key, const std::array< uint8_t, 16 >& p_init_vector)
    -> std::vector< uint8_t > {
    CryptoPP::EAX< CryptoPP::AES >::Encryption l_encryption;
    std::visit(
        [&l_encryption, &p_init_vector](auto&& key) {
            l_encryption.SetKeyWithIV(key.data(), key.size(), p_init_vector.data(), p_init_vector.size());
        },
        p_key);
    std::vector< uint8_t > l_vector;
    CryptoPP::VectorSource ss(p_raw_vector, true, new CryptoPP::AuthenticatedEncryptionFilter(l_encryption, new CryptoPP::VectorSink(l_vector)));

    return l_vector;
}

auto mt::encryption::decryptAES(const std::string& p_string, Key p_key, const std::array< uint8_t, 16 >& p_init_vector) -> std::string {
    CryptoPP::EAX< CryptoPP::AES >::Decryption l_decryption;
    std::visit(
        [&l_decryption, &p_init_vector](auto&& key) {
            l_decryption.SetKeyWithIV(key.data(), key.size(), p_init_vector.data(), p_init_vector.size());
        },
        p_key);
    std::string l_string;
    CryptoPP::StringSource ss(p_string, true, new CryptoPP::AuthenticatedDecryptionFilter(l_decryption, new CryptoPP::StringSink(l_string)));

    return l_string;
}

auto mt::encryption::decryptAES(const std::vector< uint8_t >& p_vector, Key p_key, const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t > {
    CryptoPP::EAX< CryptoPP::AES >::Decryption l_decryption;
    std::visit(
        [&l_decryption, &p_init_vector](auto&& key) {
            l_decryption.SetKeyWithIV(key.data(), key.size(), p_init_vector.data(), p_init_vector.size());
        },
        p_key);
    std::vector< uint8_t > l_vector;
    CryptoPP::VectorSource ss(p_vector, true, new CryptoPP::AuthenticatedDecryptionFilter(l_decryption, new CryptoPP::VectorSink(l_vector)));
    //    auto end = std::find(l_vector.begin(), l_vector.end(), 0);
    //    l_vector.erase(end, l_vector.end());
    return l_vector;
}