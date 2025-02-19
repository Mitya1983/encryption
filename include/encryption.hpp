#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <variant>

namespace mt::encryption {

    using Key = std::variant< std::array< uint8_t, 16 >, std::array< uint8_t, 24 >, std::array< uint8_t, 32 > >;

    [[nodiscard]] auto encodeBase64(const std::string& p_string) -> std::string;
    [[nodiscard]] auto encodeBase64(const std::vector< uint8_t >& p_vector) -> std::vector< uint8_t >;
    [[nodiscard]] auto decodeBase64(const std::string& p_string) -> std::string;
    [[nodiscard]] auto decodeBase64(const std::vector< uint8_t >& p_vector) -> std::vector< uint8_t >;

    [[nodiscard]] auto encryptAES(const std::string& p_string, Key p_key, const std::array< uint8_t, 16 >& p_init_vector) -> std::string;
    [[nodiscard]] auto encryptAES(const std::vector< uint8_t >& p_raw_vector, Key p_key, const std::array< uint8_t, 16 >& p_init_vector)
        -> std::vector< uint8_t >;
    [[nodiscard]] auto decryptAES(const std::string& p_string, Key p_key, const std::array< uint8_t, 16 >& p_init_vector) -> std::string;
    [[nodiscard]] auto decryptAES(const std::vector< uint8_t >& p_vector, Key p_key, const std::array< uint8_t, 16 >& p_init_vector) -> std::vector< uint8_t >;

}  // namespace mt::encryption

#endif  //ENCRYPTION_HPP
