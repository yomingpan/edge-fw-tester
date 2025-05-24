import asyncio
import errno
import socket
from typing import Tuple

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
    err = await loop.run_in_executor(
        None,
        lambda: socket.create_connection(addr, timeout=timeout)
               or 0,  # 成功時 err=0
    )
    return classify_errno(err)


async def _probe_udp(addr: Tuple[str, int], timeout: float = 2.0) -> str:
    # 發送空 datagram，等待 ICMP 回覆（簡化版）
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
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
    if proto == "tcp":
        return await _probe_tcp(addr, timeout=timeout)
    else:
        return await _probe_udp(addr, timeout=timeout)
