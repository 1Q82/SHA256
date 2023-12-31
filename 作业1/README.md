# SHA256

### SHA256算法的实现

​		哈希函数，又称散列算法，是一种从任何一种数据中创建小的数字“指纹”的方法。散列函数把消息或数据压缩成摘要，使得数据量变小，将数据的格式固定下来。该函数将数据打乱混合，重新创建一个叫做散列值（或哈希值）的指纹。散列值通常用一个短的随机字母和数字组成的字符串来代表。对于任意长度的消息，SHA256都会产生一个256bit长的哈希值，称作消息摘要。

​	calculate_sha256_with_nonce 函数：

    输入：字符串数据 data 和一个 uint64_t 类型的 nonce。
    输出：将数据和 nonce 连接在一起，然后计算 SHA256 散列值，并将结果以十六进制字符串形式返回。
    
    find_nonce 函数：

    输入：目标前缀字符串 target_prefix 和字符串数据 data。
    输出：在给定数据和目标前缀的情况下，查找一个 nonce 值，使得连接数据和 nonce 后的 SHA256 散列值的前缀与目标前缀相匹配。
    返回值：包含找到的 nonce 值和计算所需的时间（秒）的 std::pair<uint64_t, double>。
    
    main 函数：

    首先定义字符串数据 data 和目标前缀的向量 target_prefixes。
    对于每个目标前缀，调用 find_nonce 函数以查找符合条件的 nonce 和计算所需的时间。
    输出每个目标前缀的结果，包括目标前缀、找到的 nonce、计算所需的时间。
    
    通过不断尝试不同的 nonce 值，找到使得连接数据和 nonce 后的 SHA256 散列值的前缀与给定目标前缀相匹配的 nonce值，并测量所需的计算时间。这是一种简单的工作量证明（Proof of Work）示例，通常用于加密货币中。在本例中，我们设置了不同的目标前缀，通过尝试不同的 nonce 来寻找前缀为零的 SHA256 散列值。
