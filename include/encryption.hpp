#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <array>

namespace mt::encryption {

    [[nodiscard]] auto encodeBase64(const std::string& p_string) -> std::string;
    [[nodiscard]] auto encodeBase64(std::string&& p_string) -> std::string;
    [[nodiscard]] auto encodeBase64(const std::vector< uint8_t >& p_vector) -> std::vector< uint8_t >;
    [[nodiscard]] auto encodeBase64(std::vector< uint8_t >&& p_vector) -> std::vector< uint8_t >;
    [[nodiscard]] auto decodeBase64(const std::string& p_string) -> std::string;
    [[nodiscard]] auto decodeBase64(std::string&& p_string) -> std::string;
    [[nodiscard]] auto decodeBase64(const std::vector< uint8_t >& p_vector) -> std::vector< uint8_t >;
    [[nodiscard]] auto decodeBase64(std::vector< uint8_t >&& p_vector) -> std::vector< uint8_t >;

    [[nodiscard]] auto encryptAES(const std::string& p_string, const std::array< uint8_t, 16 >& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::string;
    [[nodiscard]] auto encryptAES(const std::string& p_string, const std::array< uint8_t, 32 >& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::string;
    [[nodiscard]] auto encryptAES(std::string&& p_string, const std::array< uint8_t, 16 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::string;
    [[nodiscard]] auto encryptAES(std::string&& p_string, const std::array< uint8_t, 32 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::string;
    [[nodiscard]] auto encryptAES(std::string&& p_string, const std::array< uint8_t, 16 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
        -> std::string;
    [[nodiscard]] auto encryptAES(std::string&& p_string, const std::array< uint8_t, 32 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
        -> std::string;
    [[nodiscard]] auto encryptAES(const std::vector< uint8_t >& p_raw_vector, const std::array< uint8_t, 16 >& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::vector< uint8_t >;
    [[nodiscard]] auto encryptAES(const std::vector< uint8_t >& p_raw_vector, const std::array< uint8_t, 32 >& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::vector< uint8_t >;
    [[nodiscard]] auto encryptAES(std::vector< uint8_t >&& p_raw_vector, std::array< uint8_t, 16 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::vector< uint8_t >;
    [[nodiscard]] auto encryptAES(std::vector< uint8_t >&& p_raw_vector, std::array< uint8_t, 32 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::vector< uint8_t >;
    [[nodiscard]] auto encryptAES(std::vector< uint8_t >&& p_raw_vector, std::array< uint8_t, 16 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
        -> std::vector< uint8_t >;
    [[nodiscard]] auto encryptAES(std::vector< uint8_t >&& p_raw_vector, std::array< uint8_t, 32 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
        -> std::vector< uint8_t >;
    [[nodiscard]] auto decryptAES(const std::string& p_string, const std::array< uint8_t, 16 >& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::string;
    [[nodiscard]] auto decryptAES(const std::string& p_string, const std::array< uint8_t, 32 >& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::string;
    [[nodiscard]] auto decryptAES(std::string&& p_string, std::array< uint8_t, 16 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::string;
    [[nodiscard]] auto decryptAES(std::string&& p_string, std::array< uint8_t, 32 >&& p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::string;
    [[nodiscard]] auto decryptAES(std::string&& p_string, std::array< uint8_t, 16 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
        -> std::string;
    [[nodiscard]] auto decryptAES(std::string&& p_string, std::array< uint8_t, 32 >&& p_key, std::array< uint8_t, 16 >&& p_init_vector)
        -> std::string;
    [[nodiscard]] auto decryptAES(const std::vector< uint8_t >& p_vector,
                                  const std::array< uint8_t, 16 >& p_key,
                                  const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t >;
    [[nodiscard]] auto decryptAES(const std::vector< uint8_t >& p_vector,
                                  const std::array< uint8_t, 32 >& p_key,
                                  const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t >;
    [[nodiscard]] auto decryptAES(std::vector< uint8_t >&& p_vector,
                                  std::array< uint8_t, 16 >&& p_key,
                                  const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t >;
    [[nodiscard]] auto decryptAES(std::vector< uint8_t >&& p_vector,
                                  std::array< uint8_t, 32 >&& p_key,
                                  const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t >;
    [[nodiscard]] auto decryptAES(std::vector< uint8_t >&& p_vector,
                                  std::array< uint8_t, 16 >&& p_key,
                                  std::array< uint8_t, 16 >&& p_init_vector) -> std::vector< uint8_t >;
    [[nodiscard]] auto decryptAES(std::vector< uint8_t >&& p_vector,
                                  std::array< uint8_t, 32 >&& p_key,
                                  std::array< uint8_t, 16 >&& p_init_vector) -> std::vector< uint8_t >;

}  // namespace tristan::encryption

#endif  //ENCRYPTION_HPP
