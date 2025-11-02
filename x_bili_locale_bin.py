# -*- coding: utf-8 -*-
"""
x-bili-locale-bin 请求头生成器。

此模块使用 Protobuf 序列化来生成 `x-bili-locale-bin` 请求头。
这个请求头是设备指纹的一部分，用于传递客户端的区域、语言和时区设置。
"""

import sys
import os
import base64

# 将 protobuf 生成的模块路径添加到系统路径中
current_dir = os.path.dirname(os.path.abspath(__file__))
proto_dir = os.path.join(current_dir, 'protobuf')
if proto_dir not in sys.path:
    sys.path.insert(0, proto_dir)

# 导入 Protobuf 生成的模块
# 注意：这些 .py 文件是由 .proto 文件编译生成的，不应手动修改。
import Locale_pb2
import LocaleIds_pb2

def generate_x_bili_locale_bin():
    """
    精确生成 `x-bili-locale-bin` 请求头的值。

    该过程严格模拟了客户端通过 Protobuf 构建和序列化区域信息的过程。
    """
    # 1. 构建 c_locale (客户端区域设置)，包含语言、文字和地区
    client_locale_ids = LocaleIds_pb2.LocaleIds(
        language="zh",
        script="Hans",  # 根据逆向分析，c_locale 包含 script (文字)
        region="CN"
    )

    # 2. 构建 s_locale (系统区域设置)，仅包含语言和地区
    system_locale_ids = LocaleIds_pb2.LocaleIds(
        language="zh",
        region="CN"  # s_locale 不包含 script
    )

    # 3. 构建顶层的 Locale 对象，整合所有区域信息
    locale_message = Locale_pb2.Locale(
        c_locale=client_locale_ids,
        s_locale=system_locale_ids,
        timezone="Asia/Shanghai",
        utc_offset="+08:00"
    )

    # 4. 将 Protobuf 对象序列化为字节串
    serialized_data = locale_message.SerializeToString()

    # 5. 对序列化后的字节进行 Base64 编码
    # B站客户端实现中移除了末尾的'='填充，此处进行模拟
    encoded_string = base64.b64encode(serialized_data).decode('utf-8').rstrip('=')

    return encoded_string

def verify_param(param: str):
    """[调试用] 解码并验证生成的参数是否符合 Protobuf 结构。"""
    try:
        # Base64解码时需要将可能被移除的'='填充补回来
        padding_needed = '=' * (4 - len(param) % 4) if len(param) % 4 != 0 else ''
        decoded_bytes = base64.b64decode(param + padding_needed)

        # 解析为 Locale Protobuf 对象
        locale_obj = Locale_pb2.Locale()
        locale_obj.ParseFromString(decoded_bytes)

        print("\n--- [调试] 解码验证 ---")
        print("解码成功，Protobuf内容如下:")
        print(str(locale_obj).strip())
    except Exception as e:
        print(f"\n--- [调试] 解码失败 ---")
        print(f"错误: {e}")

if __name__ == '__main__':
    # 生成 x-bili-locale-bin 参数
    locale_bin_header = generate_x_bili_locale_bin()
    
    print("--- 生成 x-bili-locale-bin 请求头 ---")
    print(f"生成的值: {locale_bin_header}")

    # 这是一个从真实抓包中获取的、与上述生成逻辑等价的硬编码值
    # 用于验证我们的生成逻辑是否正确
    expected_value = "Cg4KAnpoEgRIYW5zGgJDThIICgJ6aBoCQ04iDUFzaWEvU2hhbmdoYWkqBiswODowMA"
    print(f"期望的值: {expected_value}")
    print(f"生成值与期望值是否一致: {locale_bin_header == expected_value}")

    # 对期望值进行解码，以展示其内部结构
    verify_param(expected_value)
