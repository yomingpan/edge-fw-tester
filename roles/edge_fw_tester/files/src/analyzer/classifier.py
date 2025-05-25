from typing import Tuple

L4_OK = {"OPEN", "OPEN|UNKNOWN"}


def merge(result: tuple) -> str:
    # 允許 result 為 (l4, sniff) 或 (l4, sniff, extra)
    if len(result) == 3:
        l4_status, sniff, _ = result
    else:
        l4_status, sniff = result
    """
    合併 L4 與 scapy sniff 資訊。
    sniff 可能值：RST, ICMP_UNREACH, NONE
    """
    if l4_status in L4_OK:
        return "OK"
    if sniff == "RST":
        return "SERVICE_DOWN"
    if sniff == "ICMP_UNREACH":
        return "FILTERED"
    if l4_status == "FILTERED_OR_NO_SERVICE":
        return "NO_REPLY (可能被防火牆擋下或無服務)"
    return l4_status  # 其他保留原碼
