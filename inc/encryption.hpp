#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <string>
#include <vector>
#include <array>

namespace tristan::encryption {

    [[nodiscard]] auto encodeBase64(const std::string& raw_string) -> std::string;
    [[nodiscard]] auto encodeBase64(const std::vector< uint8_t >& raw_vector) -> std::vector< uint8_t >;
    [[nodiscard]] auto decodeBase64(const std::string& encoded_string) -> std::string;
    [[nodiscard]] auto decodeBase64(const std::vector< uint8_t >& encoded_vector) -> std::vector< uint8_t >;

    [[nodiscard]] auto encryptAES(const std::string& raw_string, const std::array< uint8_t, 16 >& key, const std::array< uint8_t, 16 >& init_vector)
        -> std::string;
    [[nodiscard]] auto encryptAES(const std::string& raw_string, const std::array< uint8_t, 32 >& key, const std::array< uint8_t, 16 >& init_vector)
    -> std::string;
    [[nodiscard]] auto encryptAES(const std::vector< uint8_t >& raw_vector, const std::array< uint8_t, 16 >& key, const std::array< uint8_t, 16 >& init_vector)
        -> std::vector< uint8_t >;
    [[nodiscard]] auto encryptAES(const std::vector< uint8_t >& raw_vector, const std::array< uint8_t, 32 >& key, const std::array< uint8_t, 16 >& init_vector)
        -> std::vector< uint8_t >;
    [[nodiscard]] auto decryptAES(const std::string& aes_encrypted_string, const std::array< uint8_t, 16 >& key, const std::array< uint8_t, 16 >& init_vector)
        -> std::string;
    [[nodiscard]] auto decryptAES(const std::string& aes_encrypted_string, const std::array< uint8_t, 32 >& key, const std::array< uint8_t, 16 >& init_vector)
    -> std::string;
    [[nodiscard]] auto decryptAES(const std::vector< uint8_t >& aes_encrypted_vector,
                                  const std::array< uint8_t, 16 >& key,
                                  const std::array< uint8_t, 16 >& init_vector) -> std::vector< uint8_t >;
    [[nodiscard]] auto decryptAES(const std::vector< uint8_t >& aes_encrypted_vector,
                                  const std::array< uint8_t, 32 >& key,
                                  const std::array< uint8_t, 16 >& init_vector) -> std::vector< uint8_t >;

}  // namespace tristan::encryption

#endif  //ENCRYPTION_HPP
