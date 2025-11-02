# -*- coding: utf-8 -*-
"""
模拟B站的点击上报 (click) 和心跳上报 (heartbeat) 请求。
"""

import hashlib
import time
import random
import uuid
from urllib.parse import quote

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from bvid2aid_cid import get_bilibili_aid_cid
from sign import BiliUniversalSigner
from fingerprint_database import get_fingerprint_data, get_did_info, update_did


class HeartbeatReporter:
    """
    模拟B站的心跳上报 (reportV2)，用于增加视频播放量。

    该过程分为两次上报：
    1. 开始心跳 (start): 播放开始时发送。
    2. 结束心跳 (end): 播放结束时发送，上报累积播放数据。
    """

    def __init__(self, bvid: str):
        """
        初始化心跳上报器。
        :param bvid: 目标视频的BVID。
        """
        print(f"[*] 正在为 BVID: {bvid} 初始化心跳上报器...")
        self.bvid = bvid
        self.aid, self.cid = get_bilibili_aid_cid(bvid)
        print(f"[*] 已获取 aid: {self.aid}, cid: {self.cid}")

        self.fingerprint = get_fingerprint_data()
        print("[*] 已加载设备指纹。")

        self.start_ts = int(time.time())
        self.signer = BiliUniversalSigner()
        self.url = "https://api.bilibili.com/x/report/heartbeat/mobile"
        self.headers = self._build_headers()
        print("[*] 心跳上报器初始化完成。")

    def _build_headers(self) -> dict:
        """构建通用的请求头。"""
        # 敏感信息提醒：以下请求头包含大量设备指纹信息，
        # 如 buvid, fp_local, fp_remote 等，用于模拟真实设备环境。
        # 这些是请求成功的关键，但同时也暴露了模拟设备的独一无二的身份。
        return {
            'User-Agent': self.fingerprint['user-agent'],
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "Content-Type": "application/x-www-form-urlencoded",
            'app-key': "android64",
            'bili-http-engine': "ignet",
            'buvid': self.fingerprint['buvid'],
            'env': "prod",
            'fp_local': self.fingerprint['fp_local'],
            'fp_remote': self.fingerprint['fp_remote'],
            'guestid': str(self.fingerprint['guestid']),
            'session_id': self.fingerprint['session_id'],
            'x-bili-locale-bin': self.fingerprint['x-bili-locale-bin'],
            'x-bili-metadata-ip-region': "CN",
            'x-bili-network-bin': self.fingerprint['x-bili-network-bin'],
            'x-bili-ticket': self.fingerprint.get('x-bili-ticket', ""),
            'x-bili-trace-id': self.fingerprint['x-bili-trace-id']
        }

    def _generate_payload(self, start_ts,
                          actual_played_time, is_start: bool, played_time: int = 0, total_time: int = 0,
                          paused_time: int = 0,
                          video_duration: int = 0, max_progress: int = 0, ) -> dict:
        """
        根据是“启动”还是“结束”心跳，生成请求体。
        """
        # 敏感信息提醒：payload 中包含 oaid, platform, statistics 等设备指纹。
        # oaid 是安卓设备匿名标识符，具有唯一性，是强设备指纹。
        # 建议：为降低被识别风险，确保每次请求使用的指纹组合来自同一真实设备抓包，
        # 且定期更换指纹库。
        payload = {
            # --- 视频/播放相关 ---
            'aid': self.aid,
            'cid': self.cid,
            'play_type': "1",
            'type': "3",
            'sub_type': "0",
            'epid': "0",
            'sid': "0",
            'mid': "0",
            'video_duration': str(video_duration),
            'quality': "32",
            'user_status': "0",
            'play_mode': "1",
            "epid_status": "0",
            "list_play_time": "0",
            "miniplayer_play_time": "0",
            "play_status": "0",
            "polaris_action_id": self.fingerprint['polaris_action_id'],
            "report_flow_data": "{\"flow_card_type\":\"av\",\"flow_source\":\"recent_play_online_swing\"}",
            "s_locale": "zh-Hans_CN",

            # --- 根据 is_start 变化的参数 ---
            'played_time': "0" if is_start else str(played_time),
            'total_time': "0" if is_start else str(total_time),
            'paused_time': "0" if is_start else str(paused_time),
            'last_play_progress_time': "0" if is_start else str(max_progress),
            'max_play_progress_time': "0" if is_start else str(max_progress),
            'start_ts': 0 if is_start else start_ts,
            'actual_played_time': 0 if is_start else str(actual_played_time),

            # --- 指纹/设备标识 ---
            'appkey': "1d8b6e7d45233436",
            'build': self.fingerprint['build'],
            'c_locale': "zh-Hans_CN",
            'channel': "alifenfa",
            'mobi_app': self.fingerprint['mobi_app'],
            'network_type': "1",
            'oaid': self.fingerprint['oaid'],
            'platform': self.fingerprint['platform_param'],
            'session': self.fingerprint['session'],
            'spmid': self.fingerprint['spmid'],
            'statistics': self.fingerprint['statistics'],
            'track_id': self.fingerprint.get('track_id', ''),
            'from_spmid': self.fingerprint['from_spmid'],
            'from': "7",
            'is_auto_qn': "1",
            'disable_rcmd': "0",
            'auto_play': "0",
            'cur_language': "",

            # --- 动态生成 ---
            'ts': str(int(time.time())),
        }
        return payload

    def _send_request(self, payload: dict):
        """签名并发送请求。"""
        signed_payload = self.signer.sign(payload, 0, 0)

        try:
            response = requests.post(self.url, data=signed_payload, headers=self.headers, timeout=10)
            response.raise_for_status()
            if response.json()["code"] != 0:
                print(f"[!] 请求失败: {response.json()}")
                return None
            else:
                print(f"[*] 请求成功! 响应内容: {response.json()}")
                return response.json()
        except requests.RequestException as e:
            print(f"[!] 请求失败: {e}")
            return None

    def report_start(self, video_duration: int):
        """
        上报“启动”心跳。
        :param video_duration: 视频总时长（秒）。
        """
        print("\n--- [1/2] 发送 '启动' 心跳 ---")
        payload = self._generate_payload(0, 0, is_start=True, video_duration=video_duration)
        return self._send_request(payload)

    def report_end(self, played_time: int, video_duration: int):
        """
        上报“结束”心跳。
        :param played_time: 本次会话实际播放时长（秒）。
        :param video_duration: 视频总时长（秒）。
        """
        print(f"\n--- [2/2] 发送 '结束' 心跳 (播放时长: {played_time}s) ---")
        total_time = played_time
        max_progress = played_time
        payload = self._generate_payload(
            is_start=False,
            played_time=played_time,
            total_time=total_time,
            video_duration=video_duration,
            max_progress=max_progress,
            start_ts=str(self.start_ts),
            actual_played_time=video_duration
        )
        return self._send_request(payload)


def simulate_watch(bvid: str, watch_duration: int = 65, video_duration: int = 120):
    """
    模拟一次完整的观看行为（启动 -> 结束）。
    :param bvid: 视频BVID。
    :param watch_duration: 模拟观看的时长（秒）。
    :param video_duration: 视频本身的总时长（秒）。
    """
    reporter = HeartbeatReporter(bvid=bvid)
    reporter.report_start(video_duration=video_duration)
    # 实际的观看等待可以省略，因为心跳上报不依赖于此处的延时
    reporter.report_end(played_time=watch_duration, video_duration=video_duration)
    print("\n[+] 模拟观看流程完成。")


def _get_new_did(aid: str, cid: str):
    """
    发送一个不带 'did' 的请求，以从响应中获取新的 'rpdid'。
    此函数逻辑与 click() 基本一致，以确保签名和参数匹配。
    """
    fp_data = get_fingerprint_data()
    url = "https://api.bilibili.com/x/report/click/android2"

    # 请求头与 click() 保持一致
    headers = {
        "app-key": "android64",
        "bili-http-engine": "ignet",
        "buvid": fp_data["buvid"],
        "env": "prod",
        "fp_local": fp_data["fp_local"],
        "fp_remote": fp_data["fp_remote"],
        "guestid": str(fp_data["guestid"]),
        "session_id": fp_data["session_id"],
        "user-agent": fp_data["user-agent"],
        "x-bili-locale-bin": fp_data["x-bili-locale-bin"],
        "x-bili-metadata-ip-region": "CN",
        "x-bili-network-bin": fp_data["x-bili-network-bin"],
        "x-bili-ticket": fp_data.get("x-bili-ticket", ""),
        "x-bili-trace-id": f"{uuid.uuid4().hex.replace('-', '')}:{uuid.uuid4().hex[16:]}:0:0"
    }

    # 构建POST请求体，但不包含 'did' 参数
    ftime = int(time.time()) - 1000
    stime = int(time.time())
    report_flow_data = "%7B%22flow_card_type%22%3A%22av%22%2C%22flow_source%22%3A%22recent_play_online_swing%22%7D"
    track_id = "all_49.router-pegasus-2206820-zf9n6.1757930398249.375"

    data_params = [
        ("aid", aid),
        ("auto_play", "0"),
        ("build", fp_data['build']),
        ("cid", cid),
        ("cur_language", ""),
        # ("did", fp_data['did']), # 此处特意不发送 did
        ("epid", "0"),
        ("from_spmid", fp_data['from_spmid']),
        ("ftime", str(ftime)),
        ("is_auto_qn", "1"),
        ("lv", "0"),
        ("mid", "0"),
        ("mobi_app", fp_data['mobi_app']),
        ("oaid", fp_data['oaid']),
        ("part", "1"),
        ("platform", fp_data['platform_param']),
        ("play_mode", "1"),
        ("polaris_action_id", fp_data['polaris_action_id']),
        ("report_flow_data", report_flow_data),
        ("session", fp_data['session']),
        ("sid", "0"),
        ("spmid", fp_data['spmid']),
        ("statistics", quote(fp_data['statistics'], safe='')),
        ("stime", str(stime)),
        ("sub_type", "0"),
        ("track_id", track_id),
        ("type", "3")
    ]
    post_data_str = "&".join([f"{k}={v}" for k, v in data_params])

    # 加密和签名
    encrypted_data = sign_aes(post_data_str)
    data = bytes.fromhex(encrypted_data)

    # 发送请求
    try:
        print("[DID Updater] 正在发送请求以获取新 DID...")
        response = requests.post(url, data=data, headers=headers, timeout=5)
        if response.status_code == 200:
            response_json = response.json()
            if response_json.get("code") == 0 and "data" in response_json and "rpdid" in response_json["data"]:
                new_did = response_json["data"]["rpdid"]
                print(f"[DID Updater] 成功获取新 DID: {new_did}")
                return new_did
            else:
                print(f"[DID Updater] 获取新 DID 失败: 响应内容不符合预期。响应: {response.text}")
                return None
        else:
            print(f"[DID Updater] 获取新 DID 失败: 状态码 {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"[DID Updater] 获取新 DID 时发生网络错误: {e}")
        return None


def update_did_if_needed(aid: str, cid: str):
    """
    检查 DID 是否已过期 (超过24小时)，如果需要，则获取并更新。
    """
    did_info = get_did_info()
    last_updated = did_info.get("last_updated", 0)

    # 24小时 = 86400秒
    if time.time() - last_updated > 86400:
        print("[DID Updater] DID 已过期，尝试更新...")
        new_did = _get_new_did(aid, cid)
        if new_did:
            update_did(new_did)


def click(bvid):
    """
    执行点击上报 (click) 请求。
    """
    aid, cid = get_bilibili_aid_cid(bvid)
    # 在主请求前，按需更新 DID
    update_did_if_needed(aid, cid)

    # 获取包含最新 DID 的完整指纹数据
    fp_data = get_fingerprint_data()

    url = "https://api.bilibili.com/x/report/click/android2"

    # 从指纹数据构建请求头
    headers = {
        "app-key": "android64",
        "bili-http-engine": "ignet",
        "buvid": fp_data["buvid"],
        "env": "prod",
        "fp_local": fp_data["fp_local"],
        "fp_remote": fp_data["fp_remote"],
        "guestid": str(fp_data["guestid"]),
        "session_id": fp_data["session_id"],
        "user-agent": fp_data["user-agent"],
        "x-bili-locale-bin": fp_data["x-bili-locale-bin"],
        "x-bili-metadata-ip-region": "CN",
        "x-bili-network-bin": fp_data["x-bili-network-bin"],
        "x-bili-ticket": fp_data.get("x-bili-ticket", ""), # JWT票据，通常用于已登录用户
        # 为每个请求生成独立的 trace-id
        "x-bili-trace-id": f"{uuid.uuid4().hex.replace('-', '')}:{uuid.uuid4().hex[16:]}:0:0"
    }

    # 构建POST请求体
    ftime = int(time.time()) - 1000
    stime = int(time.time())
    report_flow_data = "%7B%22flow_card_type%22%3A%22av%22%2C%22flow_source%22%3A%22recent_play_online_swing%22%7D"
    track_id = "all_49.router-pegasus-2206820-zf9n6.1757930398249.375"


    # 此处的 did 会通过 update_did_if_needed 机制定期更新，以模拟真实设备行为。
    data_params = [
        ("aid", aid),
        ("auto_play", "0"),
        ("build", fp_data['build']),
        ("cid", cid),
        ("cur_language", ""),
        ("did", fp_data['did']),
        ("epid", "0"),
        ("from_spmid", fp_data['from_spmid']),
        ("ftime", str(ftime)),
        ("is_auto_qn", "1"),
        ("lv", "0"),
        ("mid", "0"),
        ("mobi_app", fp_data['mobi_app']),
        ("oaid", fp_data['oaid']),
        ("part", "1"),
        ("platform", fp_data['platform_param']),
        ("play_mode", "1"),
        ("polaris_action_id", fp_data['polaris_action_id']),
        ("report_flow_data", report_flow_data),
        ("session", fp_data['session']),
        ("sid", "0"),
        ("spmid", fp_data['spmid']),
        ("statistics", quote(fp_data['statistics'], safe='')),
        ("stime", str(stime)),
        ("sub_type", "0"),
        ("track_id", track_id),
        ("type", "3")
    ]
    post_data_str = "&".join([f"{k}={v}" for k, v in data_params])

    # 加密请求体
    encrypted_data = sign_aes(post_data_str)
    data = bytes.fromhex(encrypted_data)

    # 发送请求
    try:
        response = requests.post(url, data=data, headers=headers)
        response.raise_for_status()
        print("响应内容:", response.text)
        return response
    except requests.RequestException as e:
        print(f"请求发生错误: {e}")
        return None


def sign_sha256(data_string: str) -> str:
    """计算数据字符串的SHA256签名 (sign)。"""
    salt = "9cafa6466a028bfb"  # 固定加盐值
    return hashlib.sha256((data_string + salt).encode('utf-8')).hexdigest()


def sign_aes(data_string: str) -> str:
    """使用AES加密数据字符串，生成最终的请求体。"""
    key = b"fd6b639dbcff0c2a1b03b389ec763c4b"  # AES密钥
    iv = b"77b07a672d57d64c"  # AES初始化向量

    # 最终待加密的数据是：POST请求体 + "&sign=" + SHA256签名
    signed_data_string = data_string + "&sign=" + sign_sha256(data_string)

    # 创建AES加密器并加密
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(signed_data_string.encode('utf-8'), AES.block_size))

    return cipher_text.hex().upper()


if __name__ == '__main__':
    bvid = ""
    watch_duration = video_duration = 0

    if not bvid:
        bvid = input("请输入BVID: ")
    if not (watch_duration and video_duration):
        watch_duration = video_duration = int(input("请输入视频（模拟观看）时长: "))

    # 批量模拟观看流程
    print("\n--- 开始批量模拟点击 ---")
    for i in range(1, 101):
        print(f"\n>>> 正在进行第 {i}/100 次循环...")
        click(bvid)
        simulate_watch(bvid=bvid, watch_duration=watch_duration, video_duration=video_duration)
        # 随机等待，模拟真人操作间隔
        sleep_duration = random.uniform(2, 5)   #这里可以修改等待间隔
        print(f"<<< 本次循环完成，随机等待 {sleep_duration:.2f} 秒后继续...")
        time.sleep(sleep_duration)
    print("\n--- 批量模拟点击全部完成 ---")
