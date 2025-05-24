import asyncio
import json
from pathlib import Path

import click

from src.config import load_flows
from src.probe.l4_probe import probe_host
from src.analyzer.classifier import merge


@click.command()
@click.argument("flows", type=click.Path(exists=True))
@click.option("--full", is_flag=True, help="啟用 L7 / sniff (需 root)")
@click.option("--output", "-o", default=None, help="Save result to JSON")
def main(flows: str, full: bool, output: str = None):  # 這裡改成預設 None，移除 3.10+ 的 str | None
    """Run edge-side firewall verification."""
    flows_cfg = load_flows(flows)

    async def _run():
        async def run_one(flow):
            l4_res = await probe_host(flow.host, flow.port, flow.proto)
            status = merge(l4_res)
            if full and getattr(flow, 'l7_check', None) and status == "OK":
                if flow.l7_check.type == "http":
                    from src.probe.l7_health import http_health
                    ok = await http_health(
                        f"http://{flow.host}:{flow.port}{flow.l7_check.path}"
                    )
                    status = "L7_OK" if ok else "L7_FAIL"
            return status

        summary = {}
        details = {}
        for f in flows_cfg:
            status = await run_one(f)
            summary[f.name] = status
            # 收集詳細資訊
            details[f.name] = {
                "result": status,
                "hostname": f.host,
                "proto": f.proto.upper(),
                "port": f.port,
                # 這裡假設 l4_probe.classify_errno 有 print 出 err，可考慮回傳 err
                # 若要更詳細，需修改 probe_host 回傳更多細節
            }
        for n, s in summary.items():
            detail = details[n]
            # 第一欄只顯示 OK 或 ERR
            short_result = 'OK' if detail['result'] == 'OK' else 'ERR'
            click.echo(f"{short_result:<6} {n:<16} {detail['hostname']:<22} {detail['proto']:<6} {detail['port']:<5} {detail['result']}")
        if output:
            Path(output).write_text(json.dumps(details, indent=2))

    asyncio.run(_run())


if __name__ == "__main__":
    main()
