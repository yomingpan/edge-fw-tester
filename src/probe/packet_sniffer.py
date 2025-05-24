"""
被 l4_probe 呼叫，啟動於 *背景 thread*，在指定期間內
監聽目標 IP/port 的回應封包。

需要 root 權限；若權限不足會自動降級為 'NONE'。
"""
from contextlib import contextmanager
from typing import Optional
import threading
import queue
import socket

try:
    from scapy.all import sniff, TCP, ICMP
except ImportError:  # scapy 未安裝或權限不足時 fallback
    sniff = None

_CAPTURE_TIME = 2.5  # 秒


@contextmanager
def capture_result(ip: str, port: int, proto: str = "tcp") -> str:
    """
    用法：
        with capture_result(ip, port) as q:
            ... # 執行 l4 探測
        result = q.get()   # RST / ICMP_UNREACH / NONE
    """
    q: "queue.Queue[str]" = queue.Queue(maxsize=1)

    def _worker():
        res = "NONE"
        if sniff is None:
            q.put(res)
            return
        bpf = f"host {ip}"
        if proto == "tcp":
            bpf += f" and tcp port {port}"
        elif proto == "udp":
            bpf += " and icmp"
        try:
            pkts = sniff(filter=bpf, timeout=_CAPTURE_TIME, store=False)
            for p in pkts:
                if TCP in p and p[TCP].flags & 0x04:   # RST
                    res = "RST"
                    break
                if ICMP in p and p[ICMP].type == 3 and p[ICMP].code == 3:
                    res = "ICMP_UNREACH"
                    break
        finally:
            q.put(res)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    try:
        yield q
    finally:
        t.join(timeout=_CAPTURE_TIME + 1)
