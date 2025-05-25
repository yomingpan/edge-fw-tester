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
@click.option("--time-out", default=2.0, show_default=True, type=float, help="L4 探測 timeout 秒數")
def main(flows: str, full: bool, output: str = None, time_out: float = 2.0):  # 這裡改成預設 None，移除 3.10+ 的 str | None
    """Run edge-side firewall verification."""
    flows_cfg = load_flows(flows)

    async def _run():
        async def run_one(flow):
            l4, sniff, extra = await probe_host(flow.host, flow.port, flow.proto, timeout=time_out)
            status = merge((l4, sniff))
            if full and getattr(flow, 'l7_check', None) and status == "OK":
                if flow.l7_check.type == "http":
                    from src.probe.l7_health import http_health
                    ok = await http_health(
                        f"http://{flow.host}:{flow.port}{flow.l7_check.path}"
                    )
                    status = "L7_OK" if ok else "L7_FAIL"
            return status, l4, sniff, extra

        summary = {}
        details = {}
        for f in flows_cfg:
            # 先即時列印「檢測中」
            test_line = f"testing   {f.name:<16} {f.host:<22} {f.proto.upper():<6} {f.port:<5}"
            click.echo(test_line)
            status, l4, sniff, extra = await run_one(f)
            short_result = 'OK' if status == 'OK' else 'ERR'
            ambiguous = (
                'NO_REPLY' in status or
                status in ('FILTERED', 'FILTERED_OR_NO_SERVICE', 'ERR_HOST_UNREACHABLE')
            )
            timeout_info = f" [timeout={extra.get('timeout')}s]" if ambiguous else ""
            double_check_info = " double_check" if extra.get('double_check') else ""
            result_line = f"{short_result:<6} {f.name:<16} {f.host:<22} {f.proto.upper():<6} {f.port:<5} {status}{timeout_info}{double_check_info}"
            # 直接覆蓋上一行（若終端支援）
            click.echo(f"\033[F{result_line}")
            summary[f.name] = status
            details[f.name] = {
                "result": status,
                "hostname": f.host,
                "proto": f.proto.upper(),
                "port": f.port,
                "l4_status": l4,
                "sniff": sniff,
                "timeout": extra.get("timeout"),
                "double_check": extra.get("double_check", False),
            }
        # 不再重複列印 summary
        if output:
            Path(output).write_text(json.dumps(details, indent=2))

    asyncio.run(_run())


if __name__ == "__main__":
    main()
