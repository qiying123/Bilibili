# -*- coding: utf-8 -*-
"""
Bilibili API 通用签名模块。

此模块实现了B站大部分API请求的参数签名算法。
它依赖于从客户端逆向得到的静态密钥表和查找表。
"""

import hashlib
from urllib.parse import quote_plus

# --- 敏感信息：静态密钥表和查找数组 ---
# 以下数据是从B站客户端逆向工程得到的静态数据，是签名算法的核心秘密。
# KEY_TABLE 包含了用于生成签名的盐值片段。
# STRING_ARRAY 是 appkey 的查找表，用于定位在 KEY_TABLE 中使用的盐值。
# 请勿修改这些数据，任何变动都会导致签名失败。

KEY_TABLE_A_HEX = (
    "488e48a0b703ddf58369cea1043eb45994e788e912020f71b295d4ac90a559e5821cca3532bbd98f6b96e8e4885a47b5dee3354d47d48ea61ca39154b9e5bccd6edfd376820c78d294e788e99667158d2e6f42520ae289bcf36569adddb6d4d499d42be68c52ec480127eb44242c6cbeef8ceaef7d84711e4f7a54253c4373a081a991dcb71fc16ba7a8a57463fed130917fb999ddb6d4d45e763a0dad7b3d62407fc3362b061943890ebc436eacd3b8861eed2e8c62a8b7d804cc2e95d81f800f83a3c4517d6cc24bd14dd24f840f02f8b1a964ee54f78d0fcd9d4d284927be890ebc43909f128d0a198db2dda0f1c4dd838f47430ce9d62a30b91d2631392dae12aa86315f738c3d71f2be2385072d2ea0aa8e2e243d503e46be4492f0acd4d4e926908364f47be17c028d430ce9d63c585326c57558c75ab17316043eb45994e788e912020f71b295d4ac90a559e5821cca3532bbd98f6b96e8e4885a47b5dee3354d47d48ea61ca39154b9e5bccd6edfd376820c78d294e788e9a2de7388b59ea696445eef09f36569adddb6d4d499d42be68c52ec480127eb44242c6cbeef8ceaef7d84711e4f7a54253c4373a081a991dcb71fc16ba7a8a57463fed130917fb999ddb6d4d48693ab68e719d15b477f62272b061943890ebc436eacd3b8861eed2e8c62a8b7d804cc2e95d81f800f83a3c4517d6cc24bd14dd24f840f02f8b1a964ee54f78d0fcd9d4d284927be890ebc43651d8b91e3cf074b78053ab0dd838f47430ce9d62a30b91d2631392dae12aa86315f738c3d71f2be2385072d2ea0aa8e2e243d503e46be4492f0acd4d4e926908364f47be17c028d430ce9d6cc520c56edcfef36e4edbd25043eb45994e788e912020f71b295d4ac90a559e5821cca3532bbd98f6b96e8e4885a47b5dee3354d47d48ea61ca39154b9e5bccd6edfd376820c78d294e788e9d0fe88d238933079831c58e1f36569adddb6d4d499d42be68c52ec480127eb44242c6cbeef8ceaef7d84711e4f7a54253c4373a081a991dcb71fc16ba7a8a57463fed130917fb999ddb6d4d4d19e85450a38d0cea473ab6c2b061943890ebc436eacd3b8861eed2e8c62a8b7d804cc2e95d81f800f83a3c4517d6cc24bd14dd24f840f02f8b1a964ee54f78d0fcd9d4d284927be890ebc4373d9ff8bc14a82bd6eca9087dd838f47430ce9d62a30b91d2631392dae12aa86315f738c3d71f2be2385072d2ea0aa8e2e243d503e46be4492f0acd4d4e926908364f47be17c028d430ce9d600000000020000000b0000000600000008000000040000000e0000000a000000010000000500000009000000030000000f00000007000000000000000c0000000d0000000000000000000000000000000f00000000000000"
)

KEY_TABLE_B_HEX = (
    "3c585326c57558c75ab17316043eb45994e788e912020f71b295d4ac90a559e5821cca3532bbd98f6b96e8e4885a47b5dee3354d47d48ea61ca39154b9e5bccd6edfd376820c78d294e788e9a2de7388b59ea696445eef09f36569adddb6d4d499d42be68c52ec480127eb44242c6cbeef8ceaef7d84711e4f7a54253c4373a081a991dcb71fc16ba7a8a57463fed130917fb999ddb6d4d48693ab68e719d15b477f62272b061943890ebc436eacd3b8861eed2e8c62a8b7d804cc2e95d81f800f83a3c4517d6cc24bd14dd24f840f02f8b1a964ee54f78d0fcd9d4d284927be890ebc43651d8b91e3cf074b78053ab0dd838f47430ce9d62a30b91d2631392dae12aa86315f738c3d71f2be2385072d2ea0aa8e2e243d503e46be4492f0acd4d4e926908364f47be17c028d430ce9d6cc520c56edcfef36e4edbd25043eb45994e788e912020f71b295d4ac90a559e5821cca3532bbd98f6b96e8e4885a47b5dee3354d47d48ea61ca39154b9e5bccd6edfd376820c78d294e788e9d0fe88d238933079831c58e1f36569adddb6d4d499d42be68c52ec480127eb44242c6cbeef8ceaef7d84711e4f7a54253c4373a081a991dcb71fc16ba7a8a57463fed130917fb999ddb6d4d4d19e85450a38d0cea473ab6c2b061943890ebc436eacd3b8861eed2e8c62a8b7d804cc2e95d81f800f83a3c4517d6cc24bd14dd24f840f02f8b1a964ee54f78d0fcd9d4d284927be890ebc4373d9ff8bc14a82bd6eca9087dd838f47430ce9d62a30b91d2631392dae12aa86315f738c3d71f2be2385072d2ea0aa8e2e243d503e46be4492f0acd4d4e926908364f47be17c028d430ce9d600000000020000000b0000000600000008000000040000000e0000000a000000010000000500000009000000030000000f00000007000000000000000c0000000d0000000000000000000000000000000f000000000000000000000000000000000000000000f87f0000c0ffffffdf41000000000000e0c1000000000000b03c000000000000f07f637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)

KEY_TABLE_C_HEX = (
    "cc520c56edcfef36e4edbd25043eb45994e788e912020f71b295d4ac90a559e5821cca3532bbd98f6b96e8e4885a47b5dee3354d47d48ea61ca39154b9e5bccd6edfd376820c78d294e788e9d0fe88d238933079831c58e1f36569adddb6d4d499d42be68c52ec480127eb44242c6cbeef8ceaef7d84711e4f7a54253c4373a081a991dcb71fc16ba7a8a57463fed130917fb999ddb6d4d4d19e85450a38d0cea473ab6c2b061943890ebc436eacd3b8861eed2e8c62a8b7d804cc2e95d81f800f83a3c4517d6cc24bd14dd24f840f02f8b1a964ee54f78d0fcd9d4d284927be890ebc4373d9ff8bc14a82bd6eca9087dd838f47430ce9d62a30b91d2631392dae12aa86315f738c3d71f2be2385072d2ea0aa8e2e243d503e46be4492f0acd4d4e926908364f47be17c028d430ce9d600000000020000000b0000000600000008000000040000000e0000000a000000010000000500000009000000030000000f00000007000000000000000c0000000d0000000000000000000000000000000f000000000000000000000000000000000000000000f87f0000c0ffffffdf41000000000000e0c1000000000000b03c000000000000f07f637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb168d01020408102040801b3652096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d0000000000000000000000000067e6096a85ae67bb72f36e3c3af54fa57f520e518c68059b"
)

STRING_ARRAY_1 = [
    "57263273bc6b67f6", "8e16697a1b4f8121", "7d336ec01856996b", "4409e2ce8ffd12b8",
    "37207f2beaebf8d7", "8d23902c1688a798", "7d089525d3611b1c", "4c6e1021617d40d9",
    "9a75abf7de2d8947", "9d5889cf67e615cd", "c034e8b74130a886", "dfca71928277209b",
    "50e1328c6a1075a1", "909879476fe22a1b", "5dce947fe22167f9", "d37be52e1501f5a5",
    "e820279abee426dd", "f3dd8d360df3ee70", "37207f2beaebf8d7", "783bbb7264451d82",
    "ae57252b0c09105d", "191c3b6b975af184", "4409e2ce8ffd12b8", "37207f2beaebf8d7",
    "8d23902c1688a798", "7d089525d3611b1c", "4c6e1021617d40d9", "9a75abf7de2d8947",
    "9d5889cf67e615cd", "c034e8b74130a886", "dfca71928277209b", "50e1328c6a1075a1",
    "909879476fe22a1b", "5dce947fe22167f9", "d37be52e1501f5a5", "e820279abee426dd",
    "f3dd8d360df3ee70", "37207f2beaebf8d7", "1d8b6e7d45233436", "bb3101000e232e27",
    "07da50c9a0bf829f", "4409e2ce8ffd12b8", "37207f2beaebf8d7", "8d23902c1688a798",
    "7d089525d3611b1c", "4c6e1021617d40d9", "9a75abf7de2d8947", "9d5889cf67e615cd",
    "c034e8b74130a886", "dfca71928277209b", "50e1328c6a1075a1", "909879476fe22a1b",
    "5dce947fe22167f9", "d37be52e1501f5a5", "e820279abee426dd", "f3dd8d360df3ee70",
    "37207f2beaebf8d7",
]

STRING_ARRAY_2 = [
    "783bbb7264451d82", "ae57252b0c09105d", "191c3b6b975af184", "4409e2ce8ffd12b8",
    "37207f2beaebf8d7", "8d23902c1688a798", "7d089525d3611b1c", "4c6e1021617d40d9",
    "9a75abf7de2d8947", "9d5889cf67e615cd", "c034e8b74130a886", "dfca71928277209b",
    "50e1328c6a1075a1", "909879476fe22a1b", "5dce947fe22167f9", "d37be52e1501f5a5",
    "e820279abee426dd", "f3dd8d360df3ee70", "37207f2beaebf8d7", "1d8b6e7d45233436",
    "bb3101000e232e27", "07da50c9a0bf829f", "4409e2ce8ffd12b8", "37207f2beaebf8d7",
    "8d23902c1688a798", "7d089525d3611b1c", "4c6e1021617d40d9", "9a75abf7de2d8947",
    "9d5889cf67e615cd", "c034e8b74130a886", "dfca71928277209b", "50e1328c6a1075a1",
    "909879476fe22a1b", "5dce947fe22167f9", "d37be52e1501f5a5", "e820279abee426dd",
    "f3dd8d360df3ee70", "37207f2beaebf8d7",
]
STRING_ARRAY_3 = [
    "1d8b6e7d45233436", "bb3101000e232e27", "07da50c9a0bf829f", "4409e2ce8ffd12b8",
    "37207f2beaebf8d7", "8d23902c1688a798", "7d089525d3611b1c", "4c6e1021617d40d9",
    "9a75abf7de2d8947", "9d5889cf67e615cd", "c034e8b74130a886", "dfca71928277209b",
    "50e1328c6a1075a1", "909879476fe22a1b", "5dce947fe22167f9", "d37be52e1501f5a5",
    "e820279abee426dd", "f3dd8d360df3ee70", "37207f2beaebf8d7"
]


class BiliUniversalSigner:
    """
    B站API通用签名器。
    严格遵循逆向工程分析出的签名逻辑。
    """

    def _select_key_table(self, seed1: int, seed2: int) -> str:
        """根据种子选择正确的密钥表 (KEY_TABLE)。"""
        if seed1 == 1 and (seed2 == 2 or seed2 == 3):
            return KEY_TABLE_A_HEX
        elif seed1 == 1:
            return KEY_TABLE_B_HEX
        else:
            return KEY_TABLE_C_HEX

    def _select_string_array(self, seed1: int, seed2: int) -> list:
        """根据种子选择正确的appkey查找数组 (STRING_ARRAY)。"""
        if seed1 == 1 and (seed2 == 2 or seed2 == 3):
            return STRING_ARRAY_1
        elif seed1 == 1:
            return STRING_ARRAY_2
        else:
            return STRING_ARRAY_3

    def _find_key_index(self, appkey: str, string_array: list) -> int:
        """在查找数组中寻找 appkey 对应的索引。"""
        try:
            return string_array.index(appkey)
        except ValueError:
            return -1

    def _reconstruct_formatted_key(self, key_index: int, key_table_hex: str) -> str:
        """
        根据索引，从密钥表中提取数据并重组为最终的哈希盐。
        此过程涉及复杂的大小端转换和拼接，严格遵循逆向逻辑。
        """
        if key_index == -1: return None

        base_offset = key_index * 8

        try:
            # 从密钥表中按特定偏移量提取4个部分，并进行字节反转（模拟小端序）
            dw1_hex = bytes.fromhex(key_table_hex[base_offset: base_offset + 8])[::-1].hex()
            dw2_hex = bytes.fromhex(key_table_hex[base_offset + 152: base_offset + 160])[::-1].hex()
            dw3_hex = bytes.fromhex(key_table_hex[base_offset + 304: base_offset + 312])[::-1].hex()
            dw4_hex = bytes.fromhex(key_table_hex[base_offset + 456: base_offset + 464])[::-1].hex()
            # 拼接成最终的哈希盐
            return dw1_hex + dw2_hex + dw3_hex + dw4_hex
        except (IndexError, ValueError):
            return None

    def sign(self, params: dict, seed1: int, seed2: int) -> str:
        """
        为给定的参数字典生成签名。

        Args:
            params (dict): 待签名的请求参数。
            seed1 (int): 种子1，用于选择密钥表和查找数组。
            seed2 (int): 种子2，用于选择密钥表和查找数组。

        Returns:
            str: 包含原始参数和 sign 的完整请求字符串。
        
        Raises:
            ValueError: 如果无法找到或生成签名密钥。
        """
        # 1. 对参数按key进行字典序排序，并拼接成URL查询字符串
        sorted_keys = sorted(params.keys())
        query_parts = [f"{key}={quote_plus(str(params[key]))}" for key in sorted_keys]
        raw_params = "&".join(query_parts)

        # 2. 根据种子选择正确的查找数组
        string_array = self._select_string_array(seed1, seed2)
        if not string_array:
            raise ValueError(f"未找到适用于种子 ({seed1}, {seed2}) 的查找数组")

        # 3. 使用 appkey 在数组中查找索引
        appkey = params.get('appkey', '')
        key_index = self._find_key_index(appkey, string_array)
        if key_index == -1:
            raise ValueError(f"AppKey '{appkey}' 在适用于种子 ({seed1}, {seed2}) 的数组中未找到")

        # 4. 根据种子选择密钥表，并根据索引重组出哈希盐
        key_table = self._select_key_table(seed1, seed2)
        key_for_hash = self._reconstruct_formatted_key(key_index, key_table)
        if not key_for_hash:
            raise ValueError(f"无法从所选密钥表中为索引 {key_index} 重建密钥")

        # 5. 将原始参数和哈希盐拼接，计算MD5签名
        string_to_hash = raw_params + key_for_hash
        final_sign = hashlib.md5(string_to_hash.encode('utf-8')).hexdigest()
        
        # 6. 返回带签名的完整请求字符串
        return f"{raw_params}&sign={final_sign}"


if __name__ == '__main__':
    # --- 签名器使用示例 ---
    signer = BiliUniversalSigner()

    # 示例1：模拟一个游客注册请求的签名 (来自 guest_id.py)
    print("--- 示例1: 模拟游客注册请求签名 ---")
    guest_reg_params ={
        "appkey": "783bbb7264451d82",
        "build": "8620300",
        "buvid": "XU0A2F702D4E80CE7A95D4E32672C849E0FF8",
        "c_locale": "zh-Hans_CN",
        "channel": "alifenfa",
        "device_info": "(此处为加密后的设备信息)",
        "disable_rcmd": "0",
        "dt": "(此处为加密后的AES密钥)",
        "local_id": "XU0A2F702D4E80CE7A95D4E32672C849E0FF8",
        "mobi_app": "android",
        "platform": "android",
        "s_locale": "zh-Hans_CN",
        "statistics": '{"appId":1,"platform":3,"version":"8.62.0","abtest":""}',
        "ts": "1758872197"
    }
    try:
        # 根据抓包分析，游客注册使用 seed1=1, seed2=0
        signed_query = signer.sign(guest_reg_params, seed1=1, seed2=0)
        print(f"模拟签名结果 (部分):\n{signed_query[:150]}...&sign={signed_query[-32:]}")
    except ValueError as e:
        print(f"[错误] {e}")

    # 示例2：模拟一个心跳上报请求的签名 (来自 click.py)
    print("\n--- 示例2: 模拟心跳上报请求签名 ---")
    heartbeat_params = {
        "appkey": "1d8b6e7d45233436",
        "build": "8620300",
        "platform": "android",
        "aid": "115098664372942",
        "cid": "31968790227",
        "ts": "1758016229"
        # ... 此处省略大量其他参数
    }
    try:
        # 根据抓包分析，心跳上报使用 seed1=0, seed2=0
        signed_query = signer.sign(heartbeat_params, seed1=0, seed2=0)
        print(f"模拟签名结果 (部分):\n{signed_query[:150]}...&sign={signed_query[-32:]}")
    except ValueError as e:
        print(f"[错误] {e}")
