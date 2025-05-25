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
@click.option("--fast/--no-fast", default=False, help="啟用並行測試（預設依序測試）")
def main(flows: str, full: bool, output: str = None, time_out: float = 2.0, fast: bool = False):  # 這裡改成預設 None，移除 3.10+ 的 str | None
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

        async def run_and_print(flow):
            status, l4, sniff, extra = await run_one(flow)
            short_result = 'OK' if status == 'OK' else 'ERR'
            ambiguous = (
                'NO_REPLY' in status or
                status in ('FILTERED', 'FILTERED_OR_NO_SERVICE', 'ERR_HOST_UNREACHABLE')
            )
            timeout_info = f" [timeout={extra.get('timeout')}s]" if ambiguous else ""
            double_check_info = " double_check" if extra.get('double_check') else ""
            result_line = f"{short_result:<6} {flow.name:<16} {flow.host:<22} {flow.proto.upper():<6} {flow.port:<5} {status}{timeout_info}{double_check_info}"
            click.echo(result_line)
            return flow.name, status, l4, sniff, extra

        if fast:
            tasks = [run_and_print(f) for f in flows_cfg]
            results = await asyncio.gather(*tasks)
        else:
            results = []
            for f in flows_cfg:
                res = await run_and_print(f)
                results.append(res)

        summary = {}
        details = {}
        for name, status, l4, sniff, extra in results:
            summary[name] = status
            details[name] = {
                "result": status,
                "hostname": next(f.host for f in flows_cfg if f.name == name),
                "proto": next(f.proto.upper() for f in flows_cfg if f.name == name),
                "port": next(f.port for f in flows_cfg if f.name == name),
                "l4_status": l4,
                "sniff": sniff,
                "timeout": extra.get("timeout"),
                "double_check": extra.get("double_check", False),
            }
        if output:
            Path(output).write_text(json.dumps(details, indent=2))

        # 統計總結
        total = len(results)
        ok_count = sum(1 for _, status, *_ in results if status.startswith('OK') or status.startswith('L7_OK'))
        err_count = total - ok_count
        click.echo(f"\nSummary: total={total}  OK={ok_count}  ERR={err_count}")

    asyncio.run(_run())


if __name__ == "__main__":
    main()
