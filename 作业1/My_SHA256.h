#include <iostream>
#include <chrono>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

std::string calculate_sha256_with_nonce(const std::string& data, uint64_t nonce) {
    // 将数据和 nonce 连接在一起
    std::ostringstream combined_data;
    combined_data << data << nonce;

    // 使用 OpenSSL 计算 SHA256 散列值
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, combined_data.str().c_str(), combined_data.str().length());
    SHA256_Final(hash, &sha256);

    // 将二进制散列值转换为十六进制字符串
    std::ostringstream hashed_data;
    hashed_data << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashed_data << std::setw(2) << static_cast<unsigned>(hash[i]);
    }

    return hashed_data.str();
}

std::pair<uint64_t, double> find_nonce(const std::string& target_prefix, const std::string& data) {
    uint64_t nonce = 0;
    auto start_time = std::chrono::high_resolution_clock::now();

    while (true) {
        // 计算带有当前 nonce 的 SHA256 散列值
        std::string hashed_data = calculate_sha256_with_nonce(data, nonce);

        // 检查散列值是否以目标前缀开头
        if (hashed_data.compare(0, target_prefix.length(), target_prefix) == 0) {
            auto end_time = std::chrono::high_resolution_clock::now();
            auto elapsed_time = std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time).count();
            return {nonce, elapsed_time};
        }

        nonce += 1;
    }
}

int main() {
    std::string data = "Blockchain@ZheiiangUniversity";
    std::vector<std::string> target_prefixes = {"00000000000000000000000000000", "000000000000000000000000000000", "0000000000000000000000000000000"};

    for (const auto& target_prefix : target_prefixes) {
        // 查找满足目标前缀条件的 nonce 和计算时间
        auto [nonce, elapsed_time] = find_nonce(target_prefix, data);
        std::cout << "Target Prefix: " << target_prefix << std::endl;
        std::cout << "Nonce: " << nonce << std::endl;
        std::cout << "Elapsed Time: " << elapsed_time << " seconds" << std::endl;
        std::cout << "=========================================" << std::endl;
    }

    return 0;
}
