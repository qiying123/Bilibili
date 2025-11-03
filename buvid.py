# -*- coding: utf-8 -*-
"""
Bilibili Buvid 生成器。

此模块用于生成 Bilibili 的设备标识符 (buvid)，这是设备指纹的关键组成部分。
"""

import hashlib
import os
import random
import uuid

# --- 设备ID生成函数 ---
# 敏感信息提醒：以下函数用于生成各种模拟的设备唯一标识符。
# 这些标识符（如 IMEI, MAC地址, OAID）是强设备指纹，能被用于追踪设备。
# 在模拟请求时，保持这些信息的一致性对避免被风控识别至关重要。

def generate_imei() -> str:
    """生成一个符合Luhn算法的15位IMEI号。"""
    base_imei = ''.join([str(random.randint(0, 9)) for _ in range(14)])
    luhn_sum = 0
    for i, digit in enumerate(base_imei):
        d = int(digit)
        if (i + 1) % 2 == 0:
            d = d * 2
            if d > 9:
                d = d - 9
        luhn_sum += d
    check_digit = (10 - (luhn_sum % 10)) % 10
    return base_imei + str(check_digit)

def generate_mac_address() -> str:
    """生成一个随机的MAC地址。"""
    return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)]).upper()

def generate_android_id() -> str:
    """生成一个随机的Android ID (16位十六进制字符串)。"""
    return os.urandom(8).hex()

def generate_drm_id() ->  str:
    """生成一个随机的DRM ID (32位十六进制字符串)。"""
    return os.urandom(16).hex()

def generate_oaid() -> str:
    """生成一个随机的OAID (UUID格式)。"""
    return str(uuid.uuid4())

# --- Buvid核心生成算法 ---

def create_buvid_from_content(content: str, prefix: str) -> str:
    """
    Bilibili buvid 的核心生成算法。
    基于给定的内容 (如设备ID) 和前缀生成 buvid。
    """
    md5_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
    char_3 = md5_hash[2]
    char_13 = md5_hash[12]
    char_23 = md5_hash[22]
    summary_str = f"{char_3}{char_13}{char_23}"
    return f"{prefix}{summary_str}{md5_hash}"

# --- Buvid生成接口 ---

def generate_buvid(strategy: str = 'drm') -> str:
    """
    根据指定策略生成一个完整的 Bilibili buvid。

    Args:
        strategy (str): 生成策略，决定了使用哪种设备ID作为生成源。
                        可选值: 'uuid', 'android_id', 'drm', 'imei', 'mac', 'oaid'。
                        默认为 'drm'，对应 'XU' 前缀的 buvid。

    Returns:
        str: 生成的 buvid。
    """
    # 敏感信息提醒：Buvid 是B站追踪设备的主要标识符之一。
    # 不同的前缀（XU, XY等）代表了不同的生成来源，模拟时应与真实设备行为保持一致。
    if strategy == 'uuid':
        device_id = str(uuid.uuid4()).replace('-', '')
        prefix = 'XW'
    elif strategy == 'android_id':
        device_id = generate_android_id()
        prefix = 'XX'
    elif strategy == 'drm':
        device_id = generate_drm_id()
        prefix = 'XU'
    elif strategy == 'imei':
        device_id = generate_imei()
        prefix = 'XZ'
    elif strategy == 'mac':
        device_id = generate_mac_address()
        prefix = 'XY'
    elif strategy == 'oaid':
        device_id = generate_oaid()
        prefix = 'XO'
    else:
        raise ValueError(f"未知的 buvid 生成策略: {strategy}")

    return create_buvid_from_content(device_id, prefix)


if __name__ == '__main__':
    print("--- 示例：基于DRM ID生成Buvid ---")
    drm_id = generate_drm_id()
    print(f"  随机DRM ID: {drm_id}")
    buvid_from_drm = create_buvid_from_content(drm_id, "XU")
    print(f"  生成的 Buvid (XU): {buvid_from_drm}")
    
    print("\n--- 示例：使用API按策略生成Buvid ---")
    print(f"  Buvid (DRM策略): {generate_buvid(strategy='drm')}")
    print(f"  Buvid (IMEI策略): {generate_buvid(strategy='imei')}")
    print(f"  Buvid (OAID策略): {generate_buvid(strategy='oaid')}")
