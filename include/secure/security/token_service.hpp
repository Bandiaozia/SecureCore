#pragma once

#include <string>
#include <string_view>

namespace secure {

struct GeneratedToken final {
    /*
     * 返回给客户端的原始令牌。
     */
    std::string value;

    /*
     * 保存到数据库中的令牌哈希。
     */
    std::string hash;
};

class TokenService final {
public:
    TokenService();

    [[nodiscard]]
    GeneratedToken generate_access_token()
        const;

    [[nodiscard]]
    GeneratedToken generate_refresh_token()
        const;

    [[nodiscard]]
    std::string hash_token(
        std::string_view token
    ) const;

private:
    [[nodiscard]]
    GeneratedToken generate_token(
        std::string_view prefix
    ) const;
};

}  // namespace secure
