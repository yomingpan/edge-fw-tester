import asyncio
import errno
import random
import socket
from typing import Tuple
from .packet_sniffer import capture_result

__all__ = ["classify_errno", "probe_host"]


def classify_errno(err: int) -> str:
    """Translate socket errno into readable status."""
    if err == 0:
        return "OPEN"
    elif err == errno.ECONNREFUSED:
        return "REFUSED"          # 主機在，但服務沒開
    elif err in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
        return "FILTERED"         # 多半是防火牆
    else:
        return f"ERR_{err}"


async def _probe_tcp(addr: Tuple[str, int], timeout: float = 2.0) -> str:
    loop = asyncio.get_running_loop()
    def try_connect():
        try:
            socket.create_connection(addr, timeout=timeout)
            return 0
        except OSError as e:
            return e.errno
    err = await loop.run_in_executor(None, try_connect)
    return classify_errno(err)


async def _probe_udp(addr: Tuple[str, int], timeout: float = 2.0) -> str:
    # 發送合法 DNS 查詢，等待 ICMP 回覆（更精確）
    def build_dns_query(domain="example.com"):
        tid = random.randint(0, 65535)
        header = tid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b"".join([bytes([len(x)]) + x.encode() for x in domain.split(".")]) + b"\x00"
        qtype = b"\x00\x01"  # A
        qclass = b"\x00\x01" # IN
        return header + qname + qtype + qclass

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            # 若 port 為 53，發送合法 DNS 查詢
            if addr[1] == 53:
                query = build_dns_query()
                s.sendto(query, addr)
            else:
                s.sendto(b"", addr)
            s.recvfrom(1024)          # 若能收到表示有人回
            return "OPEN|UNKNOWN"
        except socket.timeout:
            return "FILTERED_OR_NO_SERVICE"
        except OSError as e:
            return classify_errno(e.errno)


async def probe_host(host: str, port: int, proto: str = "tcp",
                     timeout: float = 2.0) -> str:
    loop = asyncio.get_running_loop()
    res = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addr = res[0][4]  # (ip, port)
    with capture_result(addr[0], port, proto) as q:
        if proto == "tcp":
            l4 = await _probe_tcp(addr, timeout=timeout)
        else:
            l4 = await _probe_udp(addr, timeout=timeout)
    sniff_res = q.get_nowait()  # RST / ICMP_UNREACH / NONE
    return l4, sniff_res
