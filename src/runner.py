import asyncio
import json
from pathlib import Path

import click

from src.config import load_flows
from src.probe.l4_probe import probe_host
from src.analyzer.classifier import merge


@click.command()
@click.argument("flows", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Save result to JSON")
def main(flows: str, output: str = None):  # 這裡改成預設 None，移除 3.10+ 的 str | None
    """Run edge-side firewall verification."""
    flows_cfg = load_flows(flows)

    async def _run():
        tasks = {
            f.name: probe_host(f.host, f.port, f.proto)
            for f in flows_cfg
        }
        results = {name: await coro for name, coro in tasks.items()}
        # 簡易分類（未補 sniff）
        summary = {n: merge(s) for n, s in results.items()}
        for n, s in summary.items():
            click.echo(f"{n:20} {s}")
        if output:
            Path(output).write_text(json.dumps(summary, indent=2))

    asyncio.run(_run())


if __name__ == "__main__":
    main()
