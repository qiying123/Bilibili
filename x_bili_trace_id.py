# -*- coding: utf-8 -*-
"""
x-bili-trace-id 请求头生成器。

此模块用于生成分布式链路追踪ID，模拟B站客户端的生成逻辑。
"""

import time
import random
import struct

def generate_trace_id() -> str:
    """
    生成一个符合B站格式的 trace-id。

    算法逻辑:
    1. 生成一个16字节的随机数据 payload。
    2. 获取当前Unix时间戳（秒），并将其打包为4字节的大端序字节。
    3. 使用时间戳的前3个字节覆盖 payload 的最后3个字节。
       (这模拟了客户端丢弃时间戳最低有效位的行为)
    4. 将16字节的 payload 转换为32位的十六进制字符串 (base_id)。
    5. 截取 base_id 的后16位作为 sub_id。
    6. 格式化为最终的 trace-id: "{base_id}:{sub_id}:0:0"。

    Returns:
        str: 格式化后的 trace-id。
    """
    # 1. 生成16字节的随机数据
    payload = bytearray(random.getrandbits(8) for _ in range(16))
    
    # 2. 获取Unix时间戳（秒）
    timestamp = int(time.time())

    # 3. 将时间戳的高24位（3字节）嵌入到随机数据的末尾
    ts_bytes = struct.pack('>I', timestamp)  # >I 表示大端序的4字节无符号整数
    payload[13] = ts_bytes[0] # 最高位字节
    payload[14] = ts_bytes[1]
    payload[15] = ts_bytes[2] # 第三个字节，丢弃了最低位字节 ts_bytes[3]

    # 4. 转换为十六进制字符串
    base_id = payload.hex()

    # 5. 格式化输出
    sub_id = base_id[16:]
    trace_id = f"{base_id}:{sub_id}:0:0"

    return trace_id


if __name__ == '__main__':
    print("--- 生成 x-bili-trace-id 示例 ---")
    new_trace_id = generate_trace_id()
    print(f"生成的 Trace ID: {new_trace_id}")
    print(f"Trace ID 长度: {len(new_trace_id)}") # 32 + 1 + 16 + 1 + 1 + 1 = 52
