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

auto mt::encryption::encodeBase64(std::string&& p_string) -> std::string { return mt::encryption::encodeBase64(p_string); }

auto mt::encryption::encodeBase64(const std::vector< unsigned char >& p_vector) -> std::vector< uint8_t > {
    std::vector< unsigned char > l_vector;
    CryptoPP::VectorSource l_vector_source(p_vector, true, new CryptoPP::Base64Encoder(new CryptoPP::VectorSink(l_vector), false));
//    auto end = std::find(l_vector.begin(), l_vector.end(), 0);
//    l_vector.erase(end, l_vector.end());
    return l_vector;
}

auto mt::encryption::encodeBase64(std::vector< uint8_t >&& p_vector) -> std::vector< uint8_t > { return mt::encryption::encodeBase64(p_vector); }

auto mt::encryption::decodeBase64(const std::string& p_string) -> std::string {
    std::string l_string;
    CryptoPP::StringSource l_string_source(p_string, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(l_string)));
    return l_string;
}

auto mt::encryption::decodeBase64(std::string&& p_string) -> std::string { return mt::encryption::decodeBase64(p_string); }

auto mt::encryption::decodeBase64(const std::vector< unsigned char >& p_vector) -> std::vector< uint8_t > {
    std::vector< unsigned char > l_vector;
    CryptoPP::VectorSource l_vector_source(p_vector, true, new CryptoPP::Base64Decoder(new CryptoPP::VectorSink(l_vector)));
//    auto end = std::find(l_vector.begin(), l_vector.end(), 0);
//    l_vector.erase(end, l_vector.end());
    return l_vector;
}

auto mt::encryption::decodeBase64(std::vector< uint8_t >&& p_vector) -> std::vector< uint8_t > {
    return mt::encryption::decodeBase64(p_vector);
}

auto mt::encryption::encryptAES(const std::string& p_string, const std::array< uint8_t, 16 >& p_key, const std::array< uint8_t, 16 >& p_init_vector)
    -> std::string {
    CryptoPP::EAX< CryptoPP::AES >::Encryption l_encryption;
    l_encryption.SetKeyWithIV(p_key.data(), p_key.size(), p_init_vector.data(), p_init_vector.size());
    std::string l_string;
    CryptoPP::StringSource ss(p_string, true, new CryptoPP::AuthenticatedEncryptionFilter(l_encryption, new CryptoPP::StringSink(l_string)));
    return l_string;
}

auto mt::encryption::encryptAES(const std::string& p_string, const std::array< uint8_t, 32 >& p_key, const std::array< uint8_t, 16 >& p_init_vector)
    -> std::string {
    CryptoPP::EAX< CryptoPP::AES >::Encryption l_encryption;
    l_encryption.SetKeyWithIV(p_key.data(), p_key.size(), p_init_vector.data(), p_init_vector.size());
    std::string l_string;
    CryptoPP::StringSource ss(p_string, true, new CryptoPP::AuthenticatedEncryptionFilter(l_encryption, new CryptoPP::StringSink(l_string)));
    return l_string;
}

auto mt::encryption::encryptAES(std::string&& p_string, const std::array< uint8_t, 16 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
    -> std::string {
    return mt::encryption::encryptAES(p_string, p_key, p_init_vector);
}

auto mt::encryption::encryptAES(std::string&& p_string, const std::array< uint8_t, 32 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
    -> std::string {
    return mt::encryption::encryptAES(p_string, p_key, p_init_vector);
}

auto mt::encryption::encryptAES(std::string&& p_string, const std::array< uint8_t, 16 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector) -> std::string {
    return mt::encryption::encryptAES(p_string, p_key, p_init_vector);
}

auto mt::encryption::encryptAES(std::string&& p_string, const std::array< uint8_t, 32 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector) -> std::string {
    return mt::encryption::encryptAES(p_string, p_key, p_init_vector);
}

auto mt::encryption::encryptAES(const std::vector< unsigned char >& p_vector,
                                     const std::array< uint8_t, 16 >& p_key,
                                     const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t > {
    CryptoPP::EAX< CryptoPP::AES >::Encryption l_encryption;
    l_encryption.SetKeyWithIV(p_key.data(), p_key.size(), p_init_vector.data(), p_init_vector.size());
    std::vector< unsigned char> l_vector;
    CryptoPP::VectorSource ss(p_vector, true, new CryptoPP::AuthenticatedEncryptionFilter(l_encryption, new CryptoPP::VectorSink(l_vector)));

    return l_vector;
}

auto mt::encryption::encryptAES(const std::vector< unsigned char >& p_vector,
                                     const std::array< uint8_t, 32 >& p_key,
                                     const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t > {
    CryptoPP::EAX< CryptoPP::AES >::Encryption l_encryption;
    l_encryption.SetKeyWithIV(p_key.data(), p_key.size(), p_init_vector.data(), p_init_vector.size());
    std::vector< unsigned char> l_vector;
    CryptoPP::VectorSource ss(p_vector, true, new CryptoPP::AuthenticatedEncryptionFilter(l_encryption, new CryptoPP::VectorSink(l_vector)));

    return l_vector;
}

auto mt::encryption::encryptAES(std::vector< uint8_t >&& p_vector, std::array< uint8_t, 16 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
    -> std::vector< uint8_t > {
    return mt::encryption::encryptAES(p_vector, p_key, p_init_vector);
}

auto mt::encryption::encryptAES(std::vector< uint8_t >&& p_vector, std::array< uint8_t, 32 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
    -> std::vector< uint8_t > {
    return mt::encryption::encryptAES(p_vector, p_key, p_init_vector);
}

auto mt::encryption::encryptAES(std::vector< uint8_t >&& p_vector, std::array< uint8_t, 16 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
    -> std::vector< uint8_t > {
    return mt::encryption::encryptAES(p_vector, p_key, p_init_vector);
}

auto mt::encryption::encryptAES(std::vector< uint8_t >&& p_vector, std::array< uint8_t, 32 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
    -> std::vector< uint8_t > {
    return mt::encryption::encryptAES(p_vector, p_key, p_init_vector);
}

auto mt::encryption::decryptAES(const std::string& p_string,
                                     const std::array< uint8_t, 16 >& p_key,
                                     const std::array< uint8_t, 16 >& p_init_vector) -> std::string {
    CryptoPP::EAX< CryptoPP::AES >::Decryption l_decryption;
    l_decryption.SetKeyWithIV(p_key.data(), p_key.size(), p_init_vector.data(), p_init_vector.size());
    std::string l_string;
    CryptoPP::StringSource ss(p_string, true, new CryptoPP::AuthenticatedDecryptionFilter(l_decryption, new CryptoPP::StringSink(l_string)));

    return l_string;
}

auto mt::encryption::decryptAES(const std::string& p_string,
                                     const std::array< uint8_t, 32 >& p_key,
                                     const std::array< uint8_t, 16 >& p_init_vector) -> std::string {
    CryptoPP::EAX< CryptoPP::AES >::Decryption l_decryption;
    l_decryption.SetKeyWithIV(p_key.data(), p_key.size(), p_init_vector.data(), p_init_vector.size());
    std::string l_string;
    CryptoPP::StringSource ss(p_string, true, new CryptoPP::AuthenticatedDecryptionFilter(l_decryption, new CryptoPP::StringSink(l_string)));

    return l_string;
}

auto mt::encryption::decryptAES(std::string&& p_string, std::array< uint8_t, 16 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
    -> std::string {
    return mt::encryption::decryptAES(p_string, p_key, p_init_vector);
}

auto mt::encryption::decryptAES(std::string&& p_string, std::array< uint8_t, 32 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
    -> std::string {
    return mt::encryption::decryptAES(p_string, p_key, p_init_vector);
}

auto mt::encryption::decryptAES(std::string&& p_string, std::array< uint8_t, 16 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
    -> std::string {
    return mt::encryption::decryptAES(p_string, p_key, p_init_vector);
}

auto mt::encryption::decryptAES(std::string&& p_string, std::array< uint8_t, 32 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
    -> std::string {
    return mt::encryption::decryptAES(p_string, p_key, p_init_vector);
}

auto mt::encryption::decryptAES(const std::vector< unsigned char >& p_vector,
                                     const std::array< uint8_t, 16 >& p_key,
                                     const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t > {
    CryptoPP::EAX< CryptoPP::AES >::Decryption l_decryption;
    l_decryption.SetKeyWithIV(p_key.data(), p_key.size(), p_init_vector.data(), p_init_vector.size());
    std::vector< unsigned char > l_vector;
    CryptoPP::VectorSource ss(p_vector, true, new CryptoPP::AuthenticatedDecryptionFilter(l_decryption, new CryptoPP::VectorSink(l_vector)));
//    auto end = std::find(l_vector.begin(), l_vector.end(), 0);
//    l_vector.erase(end, l_vector.end());
    return l_vector;
}

auto mt::encryption::decryptAES(const std::vector< unsigned char >& p_vector,
                                     const std::array< uint8_t, 32 >& p_key,
                                     const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t > {
    CryptoPP::EAX< CryptoPP::AES >::Decryption decrypter;
    decrypter.SetKeyWithIV(p_key.data(), p_key.size(), p_init_vector.data(), p_init_vector.size());

    std::vector< unsigned char > l_vector;
    CryptoPP::VectorSource ss(p_vector, true, new CryptoPP::AuthenticatedDecryptionFilter(decrypter, new CryptoPP::VectorSink(l_vector)));
//    auto end = std::find(l_vector.begin(), l_vector.end(), 0);
//    l_vector.erase(end, l_vector.end());
    return l_vector;
}

auto mt::encryption::decryptAES(std::vector< uint8_t >&& p_vector,
                                     std::array< uint8_t, 16 >&& p_key,
                                     const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t > {
    return mt::encryption::decryptAES(p_vector, p_key, p_init_vector);
}

auto mt::encryption::decryptAES(std::vector< uint8_t >&& p_vector,
                                     std::array< uint8_t, 32 >&& p_key,
                                     const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t > {
    return mt::encryption::decryptAES(p_vector, p_key, p_init_vector);
}

auto mt::encryption::decryptAES(std::vector< uint8_t >&& p_vector, std::array< uint8_t, 16 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
    -> std::vector< uint8_t > {
    return mt::encryption::decryptAES(p_vector, p_key, p_init_vector);
}

auto mt::encryption::decryptAES(std::vector< uint8_t >&& p_vector, std::array< uint8_t, 32 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
    -> std::vector< uint8_t > {
    return mt::encryption::decryptAES(p_vector, p_key, p_init_vector);
}
