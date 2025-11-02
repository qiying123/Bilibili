# -*- coding: utf-8 -*-
"""
会话密钥 (Session Key) 生成器。

根据B站客户端逻辑，使用 buvid 生成会话密钥。
"""

import hashlib
import time
import random

def generate_session(buvid: str) -> str:
    """
    根据给定的 buvid 生成一个会h话密钥 (Session Key)。

    算法逻辑:
    1. 获取当前时间的毫秒级时间戳。
    2. 生成一个0到999999之间的随机整数。
    3. 拼接字符串: buvid + 时间戳 + 随机数。
    4. 计算拼接后字符串的 SHA-1 哈希值作为最终结果。

    Args:
        buvid (str): 设备标识符 (buvid)，是生成会话密钥的种子。

    Returns:
        str: 40位小写的SHA-1哈希字符串，即会话密钥。
    """
    # 1. 获取当前时间的毫秒级时间戳
    current_millis = int(time.time() * 1000)

    # 2. 生成一个0到999999之间的随机整数
    random_number = random.randint(0, 999999)

    # 3. 拼接源字符串
    original_str = f"{buvid}{current_millis}{random_number}"

    # 4. 计算字符串的SHA-1哈希值并返回
    sha1_hash = hashlib.sha1(original_str.encode('utf-8')).hexdigest()
    
    return sha1_hash


if __name__ == "__main__":
    # 使用一个示例 buvid 进行测试
    example_buvid = "XU0A2F702D4E80CE7A95D4E32672C849E0FF8"

    print(f"--- 测试会话密钥生成 ---")
    print(f"输入 Buvid: {example_buvid}")
    
    session_key = generate_session(example_buvid)

    print(f"生成 Session Key: {session_key}")
    # SHA-1 哈希值的长度固定为40个字符
    print(f"Session Key 长度: {len(session_key)}")
