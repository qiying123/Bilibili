# -*- coding: utf-8 -*-
"""
x-bili-ticket 获取模块。

此模块通过 gRPC 与B站服务器通信，获取用于身份验证的 x-bili-ticket (JWT)。
该过程涉及复杂的设备指纹序列化和HMAC签名，是最高级别的设备验证流程。
"""

import sys
import os
import grpc
import hmac
import hashlib
from google.protobuf import json_format

# --- Protobuf 模块导入 ---
current_dir = os.path.dirname(os.path.abspath(__file__))
proto_dir = os.path.join(current_dir, 'protobuf')
if proto_dir not in sys.path:
    sys.path.insert(0, proto_dir)

import device_pb2
import ticket_pb2
import ticket_pb2_grpc
import fp_pb2

# --- Protobuf 消息构建函数 ---

def create_device_message(runtime_helper_data: dict) -> bytes:
    """
    构建一个 Device Protobuf 消息并序列化。
    这个消息包含了设备的基础身份信息。
    """
    device_msg = device_pb2.Device()
    
    # 根据传入的字典填充 Protobuf 消息字段
    device_msg.app_id = runtime_helper_data.get("app_id", 0)
    device_msg.build = runtime_helper_data.get("build", 0)
    device_msg.buvid = runtime_helper_data.get("buvid", "")
    device_msg.mobi_app = runtime_helper_data.get("mobi_app", "")
    device_msg.platform = "android"
    device_msg.device = runtime_helper_data.get("device", "")
    device_msg.channel = runtime_helper_data.get("channel", "")
    device_msg.brand = runtime_helper_data.get("brand", "")
    device_msg.model = runtime_helper_data.get("model", "")
    device_msg.osver = runtime_helper_data.get("osver", "")
    device_msg.guest_id = runtime_helper_data.get("guest_id", "")
    device_msg.fp_local = runtime_helper_data.get("fp_local", "")
    device_msg.fp_remote = runtime_helper_data.get("fp_remote", "")
    device_msg.version_name = runtime_helper_data.get("version_name", "")
    device_msg.fp = runtime_helper_data.get("fp", "")
    device_msg.fts = runtime_helper_data.get("fts", 0)

    return device_msg.SerializeToString()

def serialize_json_to_protobuf(json_data: dict) -> bytes:
    """
    将包含详细设备指纹的 JSON (字典) 序列化为 DeviceInfo Protobuf 字节流。
    """
    try:
        device_info_message = fp_pb2.DeviceInfo()
        json_format.ParseDict(json_data, device_info_message)
        return device_info_message.SerializeToString()
    except Exception as e:
        print(f"[错误] 序列化详细设备指纹时失败: {e}")
        return None

# --- 签名函数 ---

def calculate_sign(barr: bytes, context_map: dict, key_id: str) -> bytes:
    """
    计算 gRPC 请求的 HMAC-SHA256 签名。
    """
    # 敏感信息：这是硬编码在客户端中的 HMAC 签名密钥。
    key = b"Ezlc3tgtl"

    # 1. 构造待签名的数据：bArr + (排序后的context_map的key-value字节流)
    sorted_keys = sorted(context_map.keys())
    data_to_sign = bytearray(barr)
    for k in sorted_keys:
        data_to_sign.extend(k.encode('utf-8'))
        data_to_sign.extend(context_map[k])

    # 2. 计算 HMAC-SHA256 签名
    signature = hmac.new(key, bytes(data_to_sign), hashlib.sha256).digest()
    return signature

# --- gRPC 请求主函数 ---

def send_get_ticket_request(fingerprint_data: dict, detailed_fp_json: dict):
    """
    构造并发送 GetTicket gRPC 请求，以获取 x-bili-ticket。
    """
    # --- 1. 准备所有需要的数据 ---
    
    # a. 序列化基础设备信息 (Device PB)
    # 注意：此处的调用依赖外部传入的 fingerprint_data
    device_bin = create_device_message(fingerprint_data)
    
    # b. 序列化详细设备指纹 (DeviceInfo PB)
    fp_bin = serialize_json_to_protobuf(detailed_fp_json)
    if not fp_bin:
        return None

    # c. 准备用于签名的上下文映射
    context_for_sign = {
        "x-exbadbasket": b"",
        "x-fingerprint": fp_bin
    }
    
    # d. 调用签名函数
    signature_bytes = calculate_sign(device_bin, context_for_sign, "ec01")

    # --- 2. 构造 gRPC 请求 ---
    
    # a. 构造请求体
    request_body = ticket_pb2.GetTicketRequest(
        context=context_for_sign,
        key_id="ec01", # 密钥ID，硬编码
        sign=signature_bytes
    )

    # b. 构造请求元数据 (请求头)
    metadata = [
        ("accept", "*/*"),
        ("content-type", "application/grpc"),
        ("grpc-accept-encoding", "identity, deflate, gzip"),
        ("grpc-encoding", "gzip"),
        ("grpc-timeout", "18S"),
        ("user-agent", fingerprint_data.get("user-agent", "").replace("Mozilla/5.0 ", "grpc-c++/1.66.2 ") + " grpc-java-ignet/1.36.1"),
        ("x-bili-device-bin", device_bin)
    ]

    # --- 3. 发起 RPC 调用 ---
    try:
        print("\n--- 正在发送 GetTicket gRPC 请求 ---")
        channel = grpc.secure_channel('grpc.biliapi.net:443', grpc.ssl_channel_credentials())
        stub = ticket_pb2_grpc.TicketStub(channel)
        
        response = stub.GetTicket(request_body, metadata=metadata, timeout=15)

        print(f"[成功] gRPC 调用成功!")
        print(f"获取到的 Ticket: {response.ticket}")
        return response.ticket

    except grpc.RpcError as e:
        print(f"\n[错误] gRPC 调用失败!")
        print(f"  - 状态码: {e.code()}")
        print(f"  - 详情: {e.details()}")
        return None


if __name__ == '__main__':
    # --- 敏感信息：这是一个从真实设备抓包并解析出的极其详细的设备指纹 ---
    # 它包含了大量用于标识设备唯一性的信息，如安装应用列表、系统属性、传感器等。
    # 这是让模拟设备看起来“真实”的关键。
    detailed_fingerprint_json = {
        "accessibilityService": ["com.ss.android.ugc.aweme/.live.livehostimpl.AudioAccessibilityService"],
        "adbEnabled": 1,
        "adid": "296e4fca54a7cae5",
        "apps": "[]", # 为简洁起见，此处省略了庞大的应用列表
        "axposed": "false",
        "band": "NX659J_Z0_CN_YLL0R_V950,NX659J_Z0_CN_YLL0R_V950",
        "battery": 100,
        "brand": "nubia",
        "isRoot": True,
        "kernelVersion": "4.19.113-perf+",
        "model": "NX659J",
        "oaid": "87ce446e231a91ac651ab3c049b1e26f13c0fb1df0992330d6d7ad94947cea79",
        "osver": "11",
        "root": 1,
        "screen": "1080,2340,480",
        # ... 此处省略了大量其他字段 ...
    }

    # 在实际项目中，此数据应由 fingerprint_database 模块提供
    # 为使此脚本能独立运行，我们模拟一份基础指纹数据
    from fingerprint_database import get_fingerprint_data
    print("--- 正在加载基础设备指纹... ---")
    base_fingerprint_data = get_fingerprint_data()

    # 调用主函数以获取 ticket
    send_get_ticket_request(base_fingerprint_data, detailed_fingerprint_json)
