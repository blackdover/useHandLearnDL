def vigenere_decrypt(ciphertext, key):
    """
    使用Vigenere密钥解密密文。
    非字母字符保持不变，且不消耗密钥字符。
    """
    plaintext = []
    key_len = len(key)
    key_as_int = [ord(k.lower()) - ord('a') for k in key]

    key_idx = 0  # 密钥索引，只在处理字母时前进

    for char in ciphertext:
        if 'a' <= char <= 'z':
            c_val = ord(char) - ord('a')
            k_val = key_as_int[key_idx % key_len]
            p_val = (c_val - k_val + 26) % 26
            plaintext.append(chr(p_val + ord('a')))
            key_idx += 1
        elif 'A' <= char <= 'Z':
            c_val = ord(char) - ord('A')
            k_val = key_as_int[key_idx % key_len]
            p_val = (c_val - k_val + 26) % 26
            plaintext.append(chr(p_val + ord('A')))
            key_idx += 1
        else:
            plaintext.append(char)
    return "".join(plaintext)

def derive_key_segment(cipher_segment, plain_segment):
    """从密文片段和明文片段推导密钥片段。"""
    key_segment = []
    for i in range(len(cipher_segment)):
        c_val = ord(cipher_segment[i].lower()) - ord('a')
        p_val = ord(plain_segment[i].lower()) - ord('a')
        k_val = (c_val - p_val + 26) % 26
        key_segment.append(chr(k_val + ord('a')))
    return "".join(key_segment)

def find_repeating_pattern(s):
    """查找字符串s的最短重复模式。"""
    n = len(s)
    for length in range(1, n // 2 + 1):
        if n % length == 0:
            pattern = s[:length]
            if pattern * (n // length) == s:
                return pattern
    return s # 如果没有重复模式，则整个字符串就是模式

def solve_vigenere_bruteforce_with_hints(ciphertext_full, known_start_plain, target_word):
    """
    暴力尝试将密文中每个子串解密为target_word，并结合已知明文开头推导密钥。
    """
    print("--- 步骤1: 提取字母流并推导已知密钥片段 ---")
    # 提取密文中的所有字母，形成一个纯字母的密文流
    # 保持大小写信息以便最终解密，但密钥推导在小写上进行
    
    # 密文的字母部分 (用于密钥推导和匹配)
    ciphertext_letters_only = ""
    for char in ciphertext_full:
        if 'a' <= char <= 'z' or 'A' <= char <= 'Z':
            ciphertext_letters_only += char.lower()

    # 'flag' 对应的密文部分 (myfz)
    initial_cipher_segment = ciphertext_letters_only[:len(known_start_plain)]
    
    # 推导 'flag' 对应的密钥片段 (hnft)
    initial_key_segment = derive_key_segment(initial_cipher_segment, known_start_plain)
    print(f"根据 '{initial_cipher_segment}' -> '{known_start_plain}' 推导出的密钥起始片段: {initial_key_segment}")

    target_word_len = len(target_word)
    
    # 存储所有可能的完整密钥序列，以及它们对应的解密结果
    candidate_keys_and_results = []

    print("\n--- 步骤2: 遍历密文，假设每个子串解密为目标词 ---")
    # 遍历所有可能的起始位置，将长度为 target_word_len 的密文子串假设为加密后的 target_word
    # 注意：我们从 initial_cipher_segment 之后开始遍历，因为前面的部分已经确定
    for i in range(len(initial_key_segment), len(ciphertext_letters_only) - target_word_len + 1):
        cipher_segment_for_target = ciphertext_letters_only[i : i + target_word_len]
        
        # 推导这个假设对应的密钥片段
        target_key_segment = derive_key_segment(cipher_segment_for_target, target_word)
        
        # 现在，我们有两个密钥片段：
        # 1. initial_key_segment 对应字母流的索引 0 到 len(initial_key_segment)-1
        # 2. target_key_segment 对应字母流的索引 i 到 i + target_word_len - 1

        # 尝试构建一个完整的密钥流，并寻找其最短重复模式
        # 最长可能的密钥长度就是字母流的长度，但通常不会这么长
        # 我们可以尝试一个合理的上限，比如20
        max_key_length_to_test = 20 # 经验值，Vigenere密钥通常不会太长

        for key_len_candidate in range(1, max_key_length_to_test + 1):
            # 检查这个密钥长度是否能容纳 initial_key_segment 和 target_key_segment
            # 并且它们能够一致地形成一个重复模式
            
            # 创建一个临时的密钥数组，用 None 填充，表示未知
            temp_key_chars = [None] * key_len_candidate
            
            # 填充 initial_key_segment
            consistent = True
            for k_idx in range(len(initial_key_segment)):
                pos_in_key = k_idx % key_len_candidate
                if temp_key_chars[pos_in_key] is None:
                    temp_key_chars[pos_in_key] = initial_key_segment[k_idx]
                elif temp_key_chars[pos_in_key] != initial_key_segment[k_idx]:
                    consistent = False
                    break
            if not consistent:
                continue # 这个密钥长度不兼容 initial_key_segment

            # 填充 target_key_segment
            for k_idx in range(len(target_key_segment)):
                pos_in_key = (i + k_idx) % key_len_candidate
                if temp_key_chars[pos_in_key] is None:
                    temp_key_chars[pos_in_key] = target_key_segment[k_idx]
                elif temp_key_chars[pos_in_key] != target_key_segment[k_idx]:
                    consistent = False
                    break
            if not consistent:
                continue # 这个密钥长度不兼容 target_key_segment

            # 如果到这里仍然 consistent，说明我们找到了一个潜在的密钥模式
            # 但它可能不是最短的，或者有未填充的 '?'
            # 更好的方法是构建一个完整的推导密钥序列，然后找它的最短重复模式

            # 构造一个足够长的推导密钥序列（至少覆盖到最后一个字母）
            # 这个序列是根据密文和解密结果（假设的）推导出来的
            full_derived_key_sequence_attempt = ['?'] * len(ciphertext_letters_only)

            # 填充 initial_key_segment
            for k_idx in range(len(initial_key_segment)):
                full_derived_key_sequence_attempt[k_idx] = initial_key_segment[k_idx]

            # 填充 target_key_segment
            for k_idx in range(len(target_key_segment)):
                full_derived_key_sequence_attempt[i + k_idx] = target_key_segment[k_idx]

            # 检查这个序列是否可以由 key_len_candidate 长度的重复密钥生成
            potential_key_pattern = ""
            for k in range(key_len_candidate):
                if temp_key_chars[k] is not None:
                    potential_key_pattern += temp_key_chars[k]
                else: # 如果有任何位置未能填充，则该密钥长度不完整
                    potential_key_pattern = "" # 重置，表示无效
                    break
            
            if not potential_key_pattern:
                continue # 密钥模式不完整，跳过

            # 验证这个 potential_key_pattern 是否能生成 full_derived_key_sequence_attempt
            # 并且对于所有已知位置都匹配
            is_valid_pattern = True
            for k_idx in range(len(ciphertext_letters_only)):
                if full_derived_key_sequence_attempt[k_idx] != '?' and \
                   full_derived_key_sequence_attempt[k_idx] != potential_key_pattern[k_idx % key_len_candidate]:
                    is_valid_pattern = False
                    break
            
            if is_valid_pattern:
                # 这是一个有效的密钥候选
                # 打印信息，尝试解密
                print(f"  尝试: 密文字母索引 {i} ({cipher_segment_for_target}) -> '{target_word}'，"
                      f" 密钥长度 {key_len_candidate}，推导密钥 '{potential_key_pattern}'")
                
                decrypted_result = vigenere_decrypt(ciphertext_full, potential_key_pattern)
                
                if target_word in decrypted_result:
                    print(f"\n--- 暴力破解成功！ ---")
                    print(f"最终推导出的 Vigenere 密钥: {potential_key_pattern}")
                    print(f"解密后的 Flag: {decrypted_result}")
                    return decrypted_result # 找到答案，立即返回

    print("\n--- 未找到符合条件的密钥 ---")
    print("可能原因：")
    print("1. 目标词 'caesar' 的位置或密钥长度超出尝试范围。")
    print("2. 密文或提示有误。")
    print("3. Vigenere 密钥不是简单的重复模式，或者加密方式更复杂。")
    return None

# --- 主程序 ---
ciphertext = "myfz{hrpa_pfxddi_ypgm_xxcqkwyj_dkzcvz_2025}"
known_plain_start = "flag" # 根据 flag{...} 格式
target_word_in_flag = "caesar"

result_flag = solve_vigenere_bruteforce_with_hints(ciphertext, known_plain_start, target_word_in_flag)

