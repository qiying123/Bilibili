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
import hashlib

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
def generate_uid():
    """
    生成一个随机的 APP UID。
    """
    return str(random.randint(10000, 10100))

def generate_bili_ticket_fingerprint():
    """
    生成一组符合逻辑一致性的动态设备指纹,用于填充bili-ticket的所需指纹。
    """

    # 1. --- 时间戳 ---
    # lastDumpTs: 毫秒级当前时间戳
    current_ms = int(time.time() * 1000)
    last_dump_ts = str(current_ms)

    # boot: 毫秒级开机时间 (SystemClock.elapsedRealtime())
    # 模拟一个 1 小时到 10 天的随机开机时长
    uptime_ms = random.randint(3600 * 1000, 10 * 24 * 3600 * 1000)
    boot_time_ms = str(uptime_ms)

    # 2. --- 电池 ---
    # 随机生成一个电量 (15% - 100%)
    battery_level = random.randint(15, 100)
    str_battery_level = str(battery_level)

    # 随机生成充电状态 (0=未充电, 1=AC, 2=USB)
    # 让"未充电"的概率高一些 (e.g., 60%)
    battery_plugged_state = random.choices([0, 1, 2], weights=[0.6, 0.2, 0.2], k=1)[0]

    # *** 关键逻辑一致性 ***
    if battery_level == 100:
        # 满电时，状态固定为 FULL
        battery_status = "BATTERY_STATUS_FULL"
    elif battery_plugged_state > 0:
        # 未满电且在充电
        battery_status = "BATTERY_STATUS_CHARGING"
    else:
        # 未满电且未充电
        battery_status = "BATTERY_STATUS_DISCHARGING"

    # 电池温度 (单位: 0.1°C, 280-350 对应 28.0°C - 35.0°C)
    battery_temp = random.randint(280, 350)

    # 电池电压 (单位: mV, 3700-4400)
    battery_voltage = random.randint(3700, 4400)

    # 3. --- 屏幕与光感 ---
    # 亮度 (0-255)
    brightness = random.randint(50, 255)
    str_brightness = str(brightness)

    # 光照强度 (单位: lux)
    # 模拟一个室内光照 (10.0 - 300.0)
    light_intensity = f"{random.uniform(10.0, 300.0):.1f}"

    # 4. --- 硬件与存储 ---
    # CPU 频率 (单位: KHz)
    # 从一个常见频率列表中随机选一个
    common_cpu_freqs = [
        "1804800", "1958400", "2208000", "2419200",
        "2841600", "3000000", "3187200"
    ]
    cpu_freq = random.choice(common_cpu_freqs)

    # 可用内存 (单位: B)
    # 模拟 8GB/12GB RAM, 剩余 3-7 GB
    free_memory_gb = random.uniform(3.0, 7.0)
    free_memory = str(int(free_memory_gb * 1024 ** 3))

    # 可用存储 (单位: B)
    # 模拟 256GB/512GB ROM, 剩余 50-220 GB
    free_storage_gb = random.uniform(50.0, 220.0)
    free_storage = str(int(free_storage_gb * 1024 ** 3))
    # 5. --- 组装返回 ---
    fingerprint = {
        "battery": battery_level,
        "batteryPlugged": battery_plugged_state,
        "batterystate": battery_status,
        "batteryTemperature": battery_temp,
        "batteryVoltage": battery_voltage,
        "boot": boot_time_ms,
        "brightness": brightness,
        "cpufreq": cpu_freq,
        "freeMemory": free_memory,
        "fstorage": free_storage,
        "lastDumpTs": last_dump_ts,
        "lightIntensity": light_intensity,
        "strBattery": str_battery_level,
        "strBrightness": str_brightness,
    }

    return fingerprint

# 2. 定义用于生成指纹的静态设备信息
# MODEL = "Mi 10"
# RADIO_VERSION = "V12.5.4.0.RJCINXM"
# BUILD = 8620300
# STATISTICS = '{"appId":1,"platform":3,"version":"8.62.0","abtest":""}'
# USER_AGENT = f"Mozilla/5.0 BiliDroid/8.62.0 (bbcallen@gmail.com) 8.62.0 os/android model/{MODEL} mobi_app/android build/{BUILD} channel/alifenfa innerVer/8620310 osVer/11 network/2"
# BUILD_FINGERPRINT = f"Xiaomi/umi/umi:11/RKQ1.200826.002/{RADIO_VERSION}:user/release-keys"

MODEL = "NX659J"
RADIO_VERSION = "NX659J_Z0_CN_YLL0R_V950"
BUILD = 8620300
STATISTICS = '{"appId":1,"platform":3,"version":"8.62.0","abtest":""}'
USER_AGENT = f"Mozilla/5.0 BiliDroid/8.62.0 (bbcallen@gmail.com) 8.62.0 os/android model/{MODEL} mobi_app/android build/{BUILD} channel/alifenfa innerVer/8620310 osVer/11 network/2"
BUILD_FINGERPRINT = f"nubia/{MODEL}/{MODEL}:11/RKQ1.200826.002/{RADIO_VERSION}:user/release-keys"
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
GUID = str(uuid.uuid4())
UID = generate_uid()

# --- DID Management ---
DID_STORE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'did_store.json')
DEFAULT_DID = "aimcmJgJalRpJhugYaJYJJlupRjaplocYkaJaa"

#动态生成bili_ticket所需的fingerprint
BILI_TICKET_FINGERPRINT=generate_bili_ticket_fingerprint()

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


# --- Ticket 缓存管理 ---
TICKET_STORE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ticket_store.json')
TICKET_EXPIRATION_SECONDS = 24 * 60 * 60  # 24小时

def _get_cached_ticket() -> dict:
    """
    从 ticket_store.json 读取缓存的 ticket 信息。
    """
    if not os.path.exists(TICKET_STORE_FILE):
        return None
    try:
        with open(TICKET_STORE_FILE, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return None


def _update_cached_ticket(new_ticket: str):
    """
    更新 ticket_store.json 中的 ticket 和时间戳。
    """
    print(f"[FingerprintDB] 正在缓存新的 JWT...")
    ticket_info = {"ticket": new_ticket, "last_updated": time.time()}
    try:
        with open(TICKET_STORE_FILE, 'w') as f:
            json.dump(ticket_info, f)
        print(f"[FingerprintDB] 新 JWT 缓存成功。")
    except IOError as e:
        print(f"[FingerprintDB] 警告: 缓存 ticke 失败: {e}")


# --- 数据整合函数 ---

def get_fingerprint_data(get_ticket: bool = True):
    """
    生成并返回一个包含完整指纹数据的字典。
    这个函数是获取所有设备参数的唯一入口。
    :param get_ticket: 是否通过 gRPC 请求获取 x-bili-ticket。默认为 True。
    """
    #  准备调用 register_guest 所需的参数
    guest_reg_params = {
        "buvid": BUVID,
        "oaid": OAID,
        "model": MODEL,
        "build_fingerprint": BUILD_FINGERPRINT,
        "androidid": ANDROID_ID,
        "user-agent": USER_AGENT,
    }

    # 调用游客注册函数，获取 guest_id (这是一个网络IO操作)
    # print("[FingerprintDB] 正在注册新游客以获取 Guest ID...")
    guest_id_val = register_guest(guest_reg_params)
    if not guest_id_val:
        print("[FingerprintDB] 警告: 未能获取 Guest ID，后续请求可能会失败。")

    # 使用 BUVID 生成会话密钥
    session_key = generate_session(BUVID)

    # 从存储中获取最新的 DID
    current_did = get_did_info()['did']

    # 组装最终的完整指纹数据字典
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
        "x-bili-locale-bin": "Cg4KAnpoEgRIYW5zGgJDThIICgJ6aBoCQ04iDUFzaWEvU2hhbmdoYWkqBiswODowMA", # 硬编码的 locale 信息
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

        # --- bili-ticket需要的数据  ---
        # 1. device info
        "brand": "nubia",
        "model": MODEL,
        "osver": "11",
        "guest_id": str(guest_id_val),
        "fp": FP_LOCAL,
        "fts": int(time.time()),
        "channel": "alifenfa",
        "app_id": str(1),
        "version_name": "8.62.0",
        # 2.x-fingerprint (静态/低风险伪造)
        "accessibilityService": [
            "com.sohu.inputmethod.sogou.xiaomi/com.sohu.inputmethod.flx.quicktype.QuickAccessibilityService"],
        "adbEnabled": 0,
        "appId": "1",
        "appVersion": "8.62.0",
        "appVersionCode": "8620300",  # 与版本号匹配
        "axposed": "false",
        "batteryHealth": 2,  # 通常为2, 表示 'Good'
        "batteryPresent": True,  #
        "batteryTechnology": "Li-ion",  #
        "biometric": "1",  # 设备能力
        "biometrics": ["touchid"],  # 设备能力
        "chid": "alifenfa",  # hook中为 "alifenfa"
        "countryiso": "CN",  #
        "cpucount": 8,  # 设备能力
        "cpuvendor": "ARM",  #
        "device": "",
        "emu": "000",  # hook中为 "000". (反模拟器)
        "files": "/data/user/0/tv.danmaku.bili/files",
        "gpsSensor": "1",  # hook中为 "1". (设备能力)
        "gyroscopeSensor": "0",  # hook中为 "0". (设备能力)
        "isRoot": False,  #
        "kernelVersion": "4.19.113-perf+",  # hook中的值. (ROM信息, 与sys.fingerprint关联)
        "languages": "zh",  #
        "linearSpeedSensor": "0",  # hook中为 "0". (设备能力)
        "mem": "12219817984",  # hook中的值. (总内存, 设备能力)
        "memory": "12219817984",  # hook中的值. (总内存, 设备能力)
        "os": "android",  #
        "proc": "tv.danmaku.bili",  #
        "root": 0,  #
        "screen": "1080,2340,480",  # hook中的值. (设备能力)
        "sdkver": "0.2.4",  # hook中的值. (B站内部SDK版本)
        "sensor": "[\"Light Sensor,ZTE-Nubia\", \"Proximity Sensor,ZTE-Nubia\"]",  # hook中的值. (设备能力)
        "sensorsInfo": [  # hook中的值. (设备能力)
            {"maxRange": 10000.0, "minDelay": 500000, "name": "Light Sensor", "power": 0.13, "resolution": 1.0,
             "type": 5, "vendor": "ZTE-Nubia", "version": 1},
            {"maxRange": 10.0, "name": "Proximity Sensor", "power": 0.35, "resolution": 1.0, "type": 8,
             "vendor": "ZTE-Nubia", "version": 1}
        ],
        "speedSensor": "0",  # hook中为 "0". (设备能力)
        "strAppId": "1",  # hook中为 "1".
        "totalspace": "245671735296",  # hook中的值. (总存储, 设备能力)
        "uiVersion": "V4.5",  # hook中的值. (ROM信息)
        "usbConnected": 0,
        "virtual": "0",  # hook中为 "0". (反虚拟化)
        "virtualproc": "[]",  # hook中为 "[]". (反虚拟化)

        # (需要动态生成或保持强一致性)
        "androidapp20": "[\"1662993787184,com.eg.android.AlipayGphone,0,10.5.90,10059000,1751445204401\",\"1751460311130,com.sohu.inputmethod.sogou.xiaomi,0,10.32.21.202506031408,2166,1751460355722\",\"1751593097834,tech.pingx.watchface,0,6.1.14,151,1751894335471\",\"1755877631914,com.taobao.taobao,0,11.20.0,112000,1756457158267\",\"1751460311130,com.sohu.inputmethod.sogou.xiaomi,0,10.32.21.202506031408,2166,1751460355722\",\"1756141074856,com.autonavi.minimap,0,13.10.0,131000,1756141074856\",\"1751864869873,cn.ticktick.task,0,7.6.3.0,7630,1751888956703\",\"1662993315187,com.android.egg,0,1.0,1,1662993315187\",\"1752140206477,com.tencent.mm,0,8.0.60,2860,1752140206477\",\"1751460311130,com.sohu.inputmethod.sogou.xiaomi,0,10.32.21.202506031408,2166,1751460355722\",\"1751540299962,com.chaozh.iReader.dj.speed,0,5.3.4,25067056,1751541543039\",\"1662993275642,cn.nubia.notepad.preset,0,V6.1.30.0429,376,1662993275642\",\"1751864869873,cn.ticktick.task,0,7.6.3.0,7630,1751888956703\",\"1751539570549,com.wandoujia.phoenix2,0,8.3.4.0,803040000,1751539570549\",\"1662993801001,com.xunmeng.pinduoduo,0,7.10.0,71000,1662993801001\",\"1751460311130,com.sohu.inputmethod.sogou.xiaomi,0,10.32.21.202506031408,2166,1751460355722\",\"1751460311130,com.sohu.inputmethod.sogou.xiaomi,0,10.32.21.202506031408,2166,1751460355722\",\"1662993277165,cn.nubia.soundrecorder.preset,0,11.0.020.2108161459,110020,1662993277165\",\"1751887581696,com.jingdong.app.mall,0,12.5.0,120500,1755872630433\",\"1757151655127,com.sina.weibo,0,15.0.0,7170,1757151655127\"]",
        "androidappcnt": 150,  # 低风险伪造: 150 (一个合理值)
        "androidsysapp20": "[\"1230768000000,com.android.cts.ctsshim,1,11-6508977,30,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1230768000000,cn.nubia.voiceassist.new,1,11.0.7.1,11000071,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1230768000000,cn.nubia.browser,1,V7.9.5.2025070119a,21530,1751887192246\",\"1230768000000,com.android.phone,1,11,30,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1230768000000,com.android.stk,1,11,30,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1230768000000,cn.nubia.phonemanualintegrate.preset,1,V5.2.2.0918,214,1230768000000\",\"1230768000000,com.android.phone,1,11,30,1230768000000\",\"1230768000000,cn.nubia.gamelauncher,1,1.4.95_220825,252,1230768000000\",\"1230768000000,com.sohu.inputmethod.sogou.nubia,1,10.8.27.2108241619,1203,1230768000000\",\"1230768000000,com.android.phone,1,11,30,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1230768000000,com.android.server.telecom,1,11,30,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1230768000000,cn.nubia.diyaod,1,1.0,20210416,1230768000000\"]",
        "apps": "[\"1662993787184,com.eg.android.AlipayGphone,0,2.1.2,212,1751445204401\",\"1751460311130,com.sohu.inputmethod.sogou.xiaomi,0,10.32.21.202506031408,2166,1751460355722\",\"1751593097834,tech.pingx.watchface,0,6.1.14,151,1751894335471\",\"1230768000000,com.android.cts.ctsshim,1,11-6508977,30,1230768000000\",\"1755877631914,com.taobao.taobao,0,1.0,1,1756457158267\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1230768000000,cn.nubia.voiceassist.new,1,11.0.7.1,11000071,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1230768000000,cn.nubia.browser,1,V7.9.5.2025070119a,21530,1751887192246\",\"1230768000000,com.android.phone,1,11,30,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1751460311130,com.sohu.inputmethod.sogou.xiaomi,0,10.32.21.202506031408,2166,1751460355722\",\"1230768000000,com.android.stk,1,11,30,1230768000000\",\"1230768000000,com.android.settings,1,s.2021.1214,30,1230768000000\",\"1756141074856,com.autonavi.minimap,0,1.0,1,1756141074856\",\"1751864869873,cn.ticktick.task,0,7.6.3.0,7630,1751888956703\",\"1230768000000,cn.nubia.phonemanualintegrate.preset,1,V5.2.2.0918,214,1230768000000\",\"1230768000000,com.android.phone,1,11,30,1230768000000\",\"1230768000000,cn.nubia.gamelauncher,1,1.4.95_220825,252,1230768000000\"]",
        "band": "NX659J_Z0_CN_YLL0R_V950,NX659J_Z0_CN_YLL0R_V950",  # (ROM信息, 建议与buildId, sys.display等匹配)
        "battery": BILI_TICKET_FINGERPRINT.get("battery"),
        "batteryPlugged": BILI_TICKET_FINGERPRINT.get("batteryPlugged"),
        "batterystate": BILI_TICKET_FINGERPRINT.get("batterystate"),
        "batteryTemperature": BILI_TICKET_FINGERPRINT.get("batteryTemperature"),
        "batteryVoltage": BILI_TICKET_FINGERPRINT.get("batteryVoltage"),
        "boot": BILI_TICKET_FINGERPRINT.get("boot"),
        "brightness": BILI_TICKET_FINGERPRINT.get("brightness"),
        "cpufreq": BILI_TICKET_FINGERPRINT.get("cpufreq"),
        "freeMemory": BILI_TICKET_FINGERPRINT.get("freeMemory"),
        "fstorage": BILI_TICKET_FINGERPRINT.get("fstorage"),
        "lastDumpTs": BILI_TICKET_FINGERPRINT.get("lastDumpTs"),
        "lightIntensity": BILI_TICKET_FINGERPRINT.get("lightIntensity"),
        "strBattery": BILI_TICKET_FINGERPRINT.get("strBattery"),
        "strBrightness": BILI_TICKET_FINGERPRINT.get("strBrightness"),
        #需要逆向app寻找生成逻辑
        "t": int(time.time() * 1000) ,  # 当前时间戳, 毫秒
        "uid": UID,  #App UID
        "adid": ANDROID_ID,  # 就是ANDROID_ID
        "guid": GUID, #随机uuid
        "buvidLocal": FP_LOCAL, # 就是FP_LOCAL
        "drmid": hashlib.md5(bytes.fromhex(DRM_ID)).hexdigest(), # md5（DRM_ID）

        "buildId": "NX659J_CNCommon_V9.50",
        "props": {
            "net.hostname": "", "ro.boot.hardware": "qcom", "gsm.sim.state": "ABSENT,ABSENT",
            "ro.build.date.utc": "1662993232",
            "ro.product.device": "NX659J", "persist.sys.language": "", "ro.debuggable": "0",
            "ro.build.type": "user",
            "net.gprs.local-ip": "", "ro.build.tags": "release-keys", "http.proxy": "", "ro.serialno": "",
            "ro.boot.flash.locked": "1", "persist.sys.country": "", "ro.boot.serialno": "",
            "gsm.network.type": "Unknown,Unknown",
            "net.eth0.gw": "", "net.dns1": "", "sys.usb.state": "mtp",
            "http.agent": ""
        },
        "simulatorAttr": "{\"ro.product.model\":\"NX659J\", \"ro.bootmode\":\"unknown\", \"qemu.sf.lcd_density\":\"\", \"qemu.hw.mainkeys\":\"0\", \"init.svc.qemu-props\":\"\", \"ro.hardware\":\"qcom\", \"ro.product.device\":\"NX659J\", \"init.svc.qemud\":\"\", \"ro.kernel.android.qemud\":\"\", \"ro.kernel.qemu.gles\":\"0\", \"ro.serialno\":\"\", \"ro.kernel.qemu\":\"\", \"ro.product.name\":\"NX659J\", \"qemu.sf.fake_camera\":\"\", \"ro.bootloader\":\"unknown\"}",
        "sys": {
            "product": "NX659J", "cpu_model_name": "", "display": "NX659J_CNCommon_V9.50",
            "cpu_abi_list": "arm64-v8a,armeabi-v7a,armeabi",
            "cpu_abi_libc": "ARM", "manufacturer": "nubia", "cpu_hardware": "Qualcomm Technologies, Inc KONA",
            "cpu_processor": "AArch64 Processor rev 0 (aarch64)",
            "cpu_abi_libc64": "ARM64", "cpu_abi": "arm64-v8a", "serial": "unknown",  # 低风险: unknown
            "cpu_features": "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp",
            "fingerprint": "nubia/NX659J/NX659J:11/RKQ1.200826.002/nubia.20210910.215452:user/release-keys",
            "cpu_abi2": "", "device": "NX659J", "hardware": "qcom"
        },
    }

    # 检查 JWT 是否已过期 (超过24小时)，如果需要，则调用 gRPC 接口获取真实的 x-bili-ticket 并更新字典

    if get_ticket:
        cached_ticket_info = _get_cached_ticket()
        current_time = time.time()

        # 检查缓存是否存在且未过期
        if cached_ticket_info and (current_time - cached_ticket_info.get("last_updated", 0)) < TICKET_EXPIRATION_SECONDS:
            ticket = cached_ticket_info["ticket"]
            FINGERPRINT_DATA["x-bili-ticket"] = ticket
        else:
            if cached_ticket_info:
                print("[FingerprintDB] 缓存的 JWT 已过期，准备重新获取。")
            else:
                print("[FingerprintDB] 未找到有效 JWT 缓存，准备首次获取。")

            # 调用 gRPC 接口获取新 ticket
            new_ticket = send_get_ticket_request(FINGERPRINT_DATA)
            if new_ticket:
                print(f"[FingerprintDB] 成功获取新 JWT，已更新指纹数据。")
                FINGERPRINT_DATA["x-bili-ticket"] = new_ticket
                _update_cached_ticket(new_ticket)  # 将新 ticket 写入缓存
            else:
                print("[FingerprintDB] 警告: 未能获取 x-bili-ticket，将使用空值。")

    return FINGERPRINT_DATA


# --- 使用示例 ---
if __name__ == "__main__":
    # 默认情况下，get_fingerprint_data() 会自动完成 JWT 的获取和填充
    final_fingerprint = get_fingerprint_data()
    print("\n--- 生成的完整指纹数据库 ---")
    print(json.dumps(final_fingerprint, indent=4, ensure_ascii=False))
