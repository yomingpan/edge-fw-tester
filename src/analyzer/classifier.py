from typing import Tuple

L4_OK = {"OPEN", "OPEN|UNKNOWN"}


def merge(result: Tuple[str, str]) -> str:
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
    return l4_status  # 其他保留原碼
