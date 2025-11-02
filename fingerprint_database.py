# -*- coding: utf-8 -*-
"""
该文件集中管理了整个项目使用的伪造指纹数据。
它负责生成所有核心ID，并确保它们之间的一致性。
"""
import json
import os
import random
import secrets
import time
import uuid

from lief.Android import ANDROID_VERSIONS

# 1. 从其他模块导入所需的核心函数
from session import generate_session
from guest_id import register_guest
from buvid import generate_drm_id, create_buvid_from_content
from fp_local import generate_fp_local
from x_bili_network_bin import generate_x_bili_network_bin
from x_bili_trace_id import generate_trace_id
from x_bili_ticket import *


# --- 核心ID和设备参数定义 ---

def generate_android_id() -> str:
    """
    安全地生成一个 16 个字符（8 字节）的十六进制 AndroidID。
    """
    # secrets.token_hex(8) 生成 8 个随机字节，并将其转换为 16 个字符的十六进制字符串。
    # 例如：'296e4fca54a7cae5'
    return secrets.token_hex(8)


def generate_fake_oaid() -> str:
    """
    随机生成一个格式合法的32位小写十六进制MD5散列字符串，
    用于模拟 Bilibili 的 oaid。

    注意：此函数生成的 oaid 仅保证格式正确，不保证在 Bilibili
    服务器端被识别为真实或有效的设备标识符。
    """
    # 1. 创建一个足够随机的输入字符串。
    #    这里结合了 UUID、当前时间戳、随机数，以确保高随机性。
    random_input = f"{uuid.uuid4()}{time.time()}{random.random()}{os.urandom(16)}"

    # 2. 对输入字符串进行 MD5 哈希计算
    #    bilibili 的 oaid 格式就是标准的 MD5 散列值。
    oaid_hash = hashlib.md5(random_input.encode('utf-8')).hexdigest()

    # 3. 返回 32 位的小写十六进制字符串
    return oaid_hash
def generate_polaris_action_id_simple() -> str:
    """生成一个简单的 polaris_action_id。"""
    return uuid.uuid4().hex[:8].upper()

# 2. 定义用于生成指纹的静态设备信息
MODEL = "Mi 10"
RADIO_VERSION = "V12.5.4.0.RJCINXM"
BUILD = "8620300"
STATISTICS = '{"appId":1,"platform":3,"version":"8.62.0","abtest":""}'
USER_AGENT = f"Mozilla/5.0 BiliDroid/8.62.0 (bbcallen@gmail.com) 8.62.0 os/android model/{MODEL} mobi_app/android build/{BUILD} channel/alifenfa innerVer/8620310 osVer/11 network/2"
BUILD_FINGERPRINT = f"Xiaomi/umi/umi:11/RKQ1.200826.002/{RADIO_VERSION}:user/release-keys"

# MODEL = "NX659J"
# RADIO_VERSION = "NX659J_Z0_CN_YLL0R_V950"
# BUILD = "8620300"
# STATISTICS = '{"appId":1,"platform":3,"version":"8.62.0","abtest":""}'
# USER_AGENT = f"Mozilla/5.0 BiliDroid/8.62.0 (bbcallen@gmail.com) 8.62.0 os/android model/{MODEL} mobi_app/android build/{BUILD} channel/alifenfa innerVer/8620310 osVer/11 network/2"
# BUILD_FINGERPRINT = f"nubia/{MODEL}/{MODEL}:11/RKQ1.200826.002/{RADIO_VERSION}:user/release-keys"
# 3. 在模块加载时，生成一个唯一的底层设备ID (DRM ID)
DRM_ID = generate_drm_id()
ANDROID_ID = generate_android_id()

# 4. 基于同一个 DRM_ID 生成 buvid 和 fp_local，确保一致性
BUVID = create_buvid_from_content(DRM_ID, "XU")
FP_LOCAL = generate_fp_local(DRM_ID, MODEL, RADIO_VERSION)

x_bili_network_bin = generate_x_bili_network_bin()
x_bili_trace_id = generate_trace_id()

# 其他可以视为静态的标识符
POLARIS_ACTION_ID = generate_polaris_action_id_simple()
OAID = generate_fake_oaid()
# --- DID Management ---
DID_STORE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'did_store.json')
DEFAULT_DID = "aimcmJgJalRpJhugYaJYJJlupRjaplocYkaJaa"


def get_did_info():
    """
    从 did_store.json 读取 DID 信息。如果文件不存在，则创建它。
    """
    if not os.path.exists(DID_STORE_FILE):
        with open(DID_STORE_FILE, 'w') as f:
            json.dump({"did": DEFAULT_DID, "last_updated": 0}, f)
        return {"did": DEFAULT_DID, "last_updated": 0}

    try:
        with open(DID_STORE_FILE, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        # 如果文件损坏或为空，则重置
        with open(DID_STORE_FILE, 'w') as f:
            json.dump({"did": DEFAULT_DID, "last_updated": 0}, f)
        return {"did": DEFAULT_DID, "last_updated": 0}


def update_did(new_did: str):
    """
    更新 did_store.json 中的 DID 和时间戳。
    """
    print(f"[FingerprintDB] 更新 DID 为: {new_did}")
    did_info = {"did": new_did, "last_updated": time.time()}
    with open(DID_STORE_FILE, 'w') as f:
        json.dump(did_info, f)


# --- 数据整合函数 ---

def get_fingerprint_data():
    """
    生成并返回一个包含完整指纹数据的字典。
    这个函数是获取所有设备参数的唯一入口。
    """

    # 6. 准备调用 register_guest 所需的参数
    guest_reg_params = {
        "buvid": BUVID,
        "oaid": OAID,
        "model": MODEL,
        "build_fingerprint": BUILD_FINGERPRINT,
        "androidid": ANDROID_ID,
        "user-agent": USER_AGENT,
    }

    # 7. 调用游客注册函数，获取 guest_id (这是一个网络IO操作)
    # print("[FingerprintDB] 正在注册新游客以获取 Guest ID...")
    guest_id_val = register_guest(guest_reg_params)
    if not guest_id_val:
        print("[FingerprintDB] 警告: 未能获取 Guest ID，后续请求可能会失败。")

    # 7. 使用 BUVID 生成会话密钥
    session_key = generate_session(BUVID)

    # 从存储中获取最新的 DID
    current_did = get_did_info()['did']

    runtime_helper_data = {
        "app_id": 1,
        "build": 8620300,
        "buvid": BUVID,
        "mobi_app": "android",
        "device": "",
        "channel": "alifenfa",
        "brand": "nubia",
        "model": MODEL,
        "osver": "11",
        "guest_id": str(guest_id_val),
        "fp_local": FP_LOCAL,
        "fp_remote": FP_LOCAL,
        "version_name": "8.62.0",
        "fp": FP_LOCAL,
        "fts": int(time.time())
    }
    create_device_message(runtime_helper_data)

    # 9. 组装最终的完整指纹数据字典
    FINGERPRINT_DATA = {
        # --- 请求头中的数据 ---
        "buvid": BUVID,
        "fp_local": FP_LOCAL,
        "fp_remote": FP_LOCAL,
        "guestid": guest_id_val,  # 使用新获取的 guest_id
        "session_id": session_key[:8],
        "user-agent": USER_AGENT,
        "androidid": ANDROID_ID,
        "build_fingerprint": BUILD_FINGERPRINT,
        "x-bili-locale-bin": "Cg4KAnpoEgRIYW5zGgJDThIICgJ6aBoCQ04iDUFzaWEvU2hhbmdoYWkqBiswODowMA",
        "x-bili-network-bin": x_bili_network_bin,
        "x-bili-ticket": "",
        "x-bili-trace-id": x_bili_trace_id,

        # --- POST 请求体中的数据 ---
        "did": current_did,
        "oaid": OAID,
        "session": session_key,
        "spmid": "united.player-video-detail.0.0",
        "from_spmid": "tm.recommend.0.0",
        "statistics": STATISTICS,
        "build": BUILD,
        "mobi_app": "android",
        "platform_param": "android",
        "polaris_action_id": POLARIS_ACTION_ID,
    }
    return FINGERPRINT_DATA


# --- 使用示例 ---
if __name__ == "__main__":
    fingerprint = get_fingerprint_data()
    import json

    print("\n--- 生成的完整指纹数据库 ---")
    print(json.dumps(fingerprint, indent=4, ensure_ascii=False))
