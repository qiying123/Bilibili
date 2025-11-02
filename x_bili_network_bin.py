# -*- coding: utf-8 -*-
"""
x-bili-network-bin 请求头生成器。

此模块使用 Protobuf 序列化客户端的网络状态信息（如网络类型、质量等），
生成 `x-bili-network-bin` 请求头，作为设备指纹的一部分。
"""

import sys
import os
import base64
import time
import random

# 将 protobuf 生成的模块路径添加到系统路径中
current_dir = os.path.dirname(os.path.abspath(__file__))
proto_dir = os.path.join(current_dir, 'protobuf')
if proto_dir not in sys.path:
    sys.path.insert(0, proto_dir)

# 导入 Protobuf 生成的模块
# 注意：这些 .py 文件是由 .proto 文件编译生成的，不应手动修改。
import network_quality_pb2
import types_pb2

def generate_x_bili_network_bin() -> str:
    """
    生成 `x-bili-network-bin` 请求头的值。

    通过填充网络类型、网络质量（如成功率、速度）等信息到 Protobuf 对象中，
    然后序列化并进行 Base64 编码。其中部分数据是随机生成的，以模拟真实网络环境的波动。
    """
    # 1. 创建并填充 NetQuality 对象，描述网络质量
    quality_info = network_quality_pb2.NetQuality()
    # 随机生成成功率，模拟网络稳定性
    quality_info.success_rate = random.uniform(0.96, 0.99)
    # 随机生成网络速度（单位：bps），模拟带宽
    quality_info.speed = random.randint(9500000, 10500000)
    # 使用当前毫秒级时间戳
    quality_info.speed_timestamp = int(time.time() * 1000)

    # 2. 创建并填充 Network 对象，描述网络类型
    network_info = network_quality_pb2.Network()
    network_info.type = types_pb2.WIFI  # 网络类型，例如 WIFI
    network_info.tf = types_pb2.TF_UNKNOWN # 流量类型
    network_info.oid = "" # OID，通常为空
    network_info.cellular = types_pb2.C_NONE # 蜂窝网络类型

    # 将 quality_info 嵌套到 network_info 对象中
    network_info.quality.CopyFrom(quality_info)

    # 3. 将 Protobuf 对象序列化为字节流
    proto_bytes = network_info.SerializeToString()

    # 4. 对序列化后的字节进行 Base64 编码，生成最终的请求头值
    header_value = base64.b64encode(proto_bytes).decode('utf-8')
    return header_value

# --- 以下为开发过程中的调试辅助函数，在实际逻辑中并未使用 ---
# def compare(s1, s2):
#     """
#     [调试用] 判断字符串是否相等，并将连续不相等的位置合并输出。
#     """
#     # ... (具体实现已省略)


def verify_param(param: str):
    """[调试用] 解码并验证生成的参数是否符合 Protobuf 结构。"""
    try:
        decoded_bytes = base64.b64decode(param)
        network_obj = network_quality_pb2.Network()
        network_obj.ParseFromString(decoded_bytes)

        print("\n--- [调试] 解码验证 ---")
        print("解码成功，Protobuf内容如下:")
        print(str(network_obj).strip())
    except Exception as e:
        print(f"\n--- [调试] 解码失败 ---")
        print(f"错误: {e}")


if __name__ == '__main__':
    # 生成 x-bili-network-bin 参数
    network_bin_header = generate_x_bili_network_bin()
    
    print("--- 生成 x-bili-network-bin 请求头 ---")
    print(f"生成的值: {network_bin_header}")

    # 对生成的值进行解码验证，以展示其内部结构
    verify_param(network_bin_header)
