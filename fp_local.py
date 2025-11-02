# -*- coding: utf-8 -*-
"""
本地设备指纹 (fp_local) 生成器。

fp_local 是B站设备指纹系统中的一个关键标识，与 buvid 紧密相关。
"""

import hashlib
import time
import os

def _calculate_checksum(input_str: str) -> str:
    """
    为给定的十六进制字符串计算一个8位校验和。

    算法：累加字符串中每两个字符代表的十六进制数，然后对256取模。
    """
    total_sum = 0
    # 校验和只计算字符串的前64个字符
    limit = min(len(input_str), 64)

    # 步长为2，遍历字符串，每次取2个字符作为一个十六进制数
    for i in range(0, limit, 2):
        hex_pair = input_str[i:i + 2]
        try:
            value = int(hex_pair, 16)
            total_sum += value
        except ValueError:
            # 如果子字符串不是有效的十六进制，则忽略
            pass

    # 取模并格式化为两位小写十六进制字符串
    checksum = "{:02x}".format(total_sum % 256)
    return checksum

def generate_fp_local(drm_id: str, model: str, radio_version: str) -> str:
    """
    生成本地设备指纹 (fp_local)。

    敏感信息提醒：fp_local 是一个强设备指纹。为保证模拟的真实性，
    其生成源 (drm_id, model, radio_version) 必须与指纹库中其他参数保持一致。

    算法流程:
    1. 拼接源字符串: drm_id + model + radio_version
    2. 计算拼接后字符串的 MD5 哈希。
    3. 获取格式化的时间戳 (YYYYMMDDHHmmss)。
    4. 生成一个16位的随机十六进制字符串。
    5. 拼接主体: md5_hash + timestamp + random_hex。
    6. 计算第5步结果的校验和。
    7. 最终结果: 第5步结果 + 校验和。

    Args:
        drm_id (str): 设备DRM ID，应与生成buvid的ID一致。
        model (str): 设备型号。
        radio_version (str): 设备的基带版本。

    Returns:
        str: 生成的 fp_local 字符串 (长度为64)。
    """
    # 1. 拼接源字符串
    seed_str = f"{drm_id}{model}{radio_version}"

    # 2. 计算MD5哈希
    md5_hash = hashlib.md5(seed_str.encode()).hexdigest()

    # 3. 获取时间戳 (格式: YYYYMMDDHHmmss)
    timestamp = time.strftime("%Y%m%d%H%M%S", time.localtime())

    # 4. 生成16位随机十六进制串
    random_hex = os.urandom(8).hex()

    # 5. 拼接指纹主体
    main_part = f"{md5_hash}{timestamp}{random_hex}"

    # 6. 计算并附加校验和
    checksum = _calculate_checksum(main_part)
    final_fp = main_part + checksum

    return final_fp


if __name__ == '__main__':
    # 为了独立测试，我们随机生成一个示例DRM ID
    sample_drm_id = os.urandom(16).hex()
    sample_model = "NX659J"
    sample_radio = "NX659J_Z0_CN_YLL0R_V950"
    
    print("--- 使用以下信息生成 fp_local ---")
    print(f"  DRM ID (示例): {sample_drm_id}")
    print(f"  Model: {sample_model}")
    print(f"  Radio: {sample_radio}")
    
    fp = generate_fp_local(sample_drm_id, sample_model, sample_radio)
    
    print(f"\n生成的 fp_local: {fp}")
    # 长度固定为 64 位: 32 (md5) + 14 (timestamp) + 16 (random) + 2 (checksum) = 64
    print(f"fp_local 长度: {len(fp)}")
