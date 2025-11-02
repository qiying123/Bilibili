# -*- coding: utf-8 -*-
"""
BVID 转换工具。

通过调用B站公开API，将视频的BVID转换为aid和cid。
"""

import requests
import json


def get_bilibili_aid_cid(bvid: str):
    """
    使用BVID获取视频的aid和cid。

    :param bvid: 视频的BV号 (例如: "BV1FcxozgEtU")。
    :return: 包含aid和cid的元组 (aid, cid)，失败则返回 (None, None)。
    """
    # 注意：这是一个公开的Web API，不需要复杂的设备指纹。
    url = f"https://api.bilibili.com/x/web-interface/view?bvid={bvid}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Referer': f'https://www.bilibili.com/video/{bvid}'
    }

    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()

        if data.get('code') == 0 and 'data' in data:
            video_data = data['data']
            aid = video_data.get('aid')
            cid = None

            # 优先从 pages 列表中获取第一个分P的 cid，这对于多P视频更可靠。
            if 'pages' in video_data and isinstance(video_data['pages'], list) and len(video_data['pages']) > 0:
                cid = video_data['pages'][0].get('cid')

            # 如果 pages 中没有，则尝试从顶层获取 cid 作为备用。
            if not cid:
                cid = video_data.get('cid')

            if aid and cid:
                return aid, cid
            else:
                print(f"[-] 未能在API响应中找到aid或cid。aid: {aid}, cid: {cid}")
                return None, None
        else:
            print(f"[-] API返回错误: code={data.get('code')}, message={data.get('message')}")
            return None, None

    except requests.exceptions.RequestException as e:
        print(f"[-] 请求发生网络错误: {e}")
        return None, None
    except json.JSONDecodeError:
        print("[-] 解析JSON响应失败")
        return None, None


if __name__ == "__main__":
    test_bvid = "BV1FcxozgEtU"
    print(f"--- 测试BVID转换: {test_bvid} ---")
    
    video_aid, video_cid = get_bilibili_aid_cid(test_bvid)

    if video_aid and video_cid:
        print(f"[+] 查询成功!")
        print(f"    BVID: {test_bvid}")
        print(f"    aid:  {video_aid}")
        print(f"    cid:  {video_cid}")
    else:
        print(f"[-] 查询失败。")
