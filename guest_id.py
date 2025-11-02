# -*- coding: utf-8 -*-
"""
游客ID (guest_id) 注册模块。

通过向B站服务器发送加密的设备指纹信息，注册一个临时游客身份，并获取 guest_id。
"""

import json
import time
import random
import base64
import requests

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad
from sign import BiliUniversalSigner

# --- 常量定义 ---
# 敏感信息：这是硬编码在客户端中，用于加密通信密钥的RSA公钥。
# 它是游客注册加密流程中的关键部分。
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDjb4V7EidX/ym28t2ybo0U6t0n
6p4ej8VjqKHg100va6jkNbNTrLQqMCQCAYtXMXXp2Fwkk6WR+12N9zknLjf+C9sx
/+l48mjUU8RqahiFD1XT/u2e0m2EN029OhCgkHx3Fc/KlFSIbak93EH/XlYis0w+
Xl69GV6klzgxW6d2xQIDAQAB
-----END PUBLIC KEY-----"""
AES_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234GHIJKLMNOPQRSTUVWXYZ0123456789"


def _generate_encrypted_params(device_info_map: dict) -> tuple[str, str]:
    """
    [私有] 生成加密后的 dt 和 device_info 参数。

    此函数采用混合加密方案：
    1. 生成一个随机的16位字符串作为AES的密钥和初始化向量(IV)。
    2. 使用 AES-CBC 模式加密实际的设备信息 (device_info)。
    3. 使用硬编码的 RSA 公钥加密第1步生成的AES密钥。
    4. 返回 RSA加密后的密钥 (dt) 和 AES加密后的设备信息 (device_info)。
    """
    json_payload = json.dumps(device_info_map, separators=(',', ':'))
    
    # 1. 生成一次性的AES密钥和IV
    aes_key_iv = ''.join(random.choices(AES_CHARSET, k=16))
    
    # 2. 使用AES加密设备信息
    cipher_aes = AES.new(aes_key_iv.encode('utf-8'), AES.MODE_CBC, aes_key_iv.encode('utf-8'))
    encrypted_payload_bytes = cipher_aes.encrypt(pad(json_payload.encode('utf-8'), AES.block_size))
    device_info = encrypted_payload_bytes.hex().upper()
    
    # 3. 使用RSA公钥加密AES密钥
    rsa_key = RSA.import_key(PUBLIC_KEY)
    cipher_rsa = PKCS1_v1_5.new(rsa_key)
    encrypted_key_bytes = cipher_rsa.encrypt(aes_key_iv.encode('utf-8'))
    dt = base64.b64encode(encrypted_key_bytes).decode('utf-8')
    
    return dt, device_info

def register_guest(device_params: dict) -> str:
    """
    执行游客注册流程，返回从服务器获取的 guest_id。

    Args:
        device_params: 包含核心设备指纹的字典 (buvid, oaid, model等)。

    Returns:
        成功时返回 guest_id 字符串，失败时返回空字符串。
    """
    # 1. 准备用于加密的设备信息子集
    # 敏感信息提醒：这些都是强设备指纹，用于向服务器证明设备的“真实性”。
    encryption_info = {
        "DeviceType": "Android",
        "fts": str(int(time.time())),
        "Buvid": device_params["buvid"],
        "BuildDisplay": f'{device_params["model"]}_CNCommon_V9.50',
        "BuildBrand": "nubia",
        "OAID": device_params["oaid"],
        "BuildFingerprint": device_params["build_fingerprint"],
        "AndroidID": device_params["androidid"],
        "BuildHost": "ubuntu"
    }

    # 2. 加密设备信息，获取 dt 和 device_info
    dt, device_info = _generate_encrypted_params(encryption_info)

    # 3. 准备用于签名的完整请求参数
    payload = {
        "appkey": "783bbb7264451d82",
        "build": "8620300",
        "buvid": device_params["buvid"],
        "c_locale": "zh-Hans_CN",
        "channel": "alifenfa",
        "device_info": device_info, # AES加密的设备信息
        "disable_rcmd": "0",
        "dt": dt,                   # RSA加密的AES密钥
        "local_id": device_params["buvid"], # local_id 通常与 buvid 相同
        "mobi_app": "android",
        "platform": "android",
        "s_locale": "zh-Hans_CN",
        "statistics": '{"appId":1,"platform":3,"version":"8.62.0","abtest":""}',
        "ts": str(int(time.time())),
    }

    # 4. 计算请求签名
    signer = BiliUniversalSigner()
    signed_payload = signer.sign(payload, 1, 0)

    # 5. 发送POST请求
    url = "https://passport.bilibili.com/x/passport-user/guest/reg"
    headers = {
        "User-Agent": device_params["user-agent"],
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "app-key": "android64",
        "bili-http-engine": "ignet",
        "env": "prod",
    }

    try:
        response = requests.post(url, data=signed_payload, headers=headers, timeout=10)
        response.raise_for_status()
        response_data = response.json()

        # 6. 从响应中解析并返回 guest_id
        if response_data.get("code") == 0:
            return response_data.get("data", {}).get("guest_id", "")
        else:
            print(f"[GuestID] 获取失败: {response.text}")
            return ""
    except requests.RequestException as e:
        print(f"[GuestID] 请求时发生网络错误: {e}")
        return ""


if __name__ == '__main__':
    # 这是一个演示，展示如何独立使用此模块。
    # 在实际项目中，这些参数应由 fingerprint_database 模块统一提供。
    print("--- 正在独立测试 Guest ID 注册模块 ---")
    try:
        from fingerprint_database import get_fingerprint_data
        print("从 fingerprint_database 加载指纹...")
        test_params = get_fingerprint_data()
        guest_id = register_guest(test_params)
        if guest_id:
            print(f"成功获取 Guest ID: {guest_id}")
        else:
            print("获取 Guest ID 失败。")
    except ImportError:
        print("错误：无法导入 fingerprint_database。请确保该文件存在且路径正确。")
