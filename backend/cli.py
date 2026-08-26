"""Headless CLI — run a pipeline from the terminal (3E sub-micro-paso 1).

Usage:
    python -m backend.cli --target example.com --pipeline fast
    python -m backend.cli --target example.com --pipeline nuclear --json

Pure headless by design: no web, no DB writes. Use the web UI for runs that
must be persisted and comparable in History.
"""
import argparse
import asyncio
import json
import sys

from backend.config import PIPELINES
from backend.pipeline import PipelineRunner
from backend.validators import validate_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="backend.cli",
        description="Run a security pipeline headless (no web, no DB).",
    )
    parser.add_argument("--target", required=True,
                        help="Target host (e.g. example.com or 10.0.0.5)")
    parser.add_argument("--pipeline", default="fast", choices=sorted(PIPELINES),
                        help="Pipeline mode (default: fast)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Print the full result as JSON instead of a text summary")
    return parser


def format_text(result: dict) -> str:
    """One-screen human summary of a pipeline result."""
    lines = [
        f"mode: {result.get('mode')}",
        f"target: {result.get('target')}",
        f"status: {result.get('status')}",
        f"elapsed: {result.get('elapsed_seconds')}s",
        f"tools: {result.get('total_tools')}",
        f"findings: {len(result.get('findings', []))}",
        f"score: {result.get('score')}",
    ]
    phases = result.get("phases") or {}
    if phases:
        lines.append("phases:")
        for name, tools in phases.items():
            ok = sum(1 for t in tools.values() if isinstance(t, dict) and t.get("success"))
            lines.append(f"  {name}: {ok}/{len(tools)} ok")
    return "\n".join(lines)


async def run_cli(args: argparse.Namespace) -> int:
    ok, reason = validate_target(args.target)
    if not ok:
        print(f"error: invalid target: {reason}", file=sys.stderr)
        return 1

    runner = PipelineRunner(pipeline_id=0, mode=args.pipeline,
                            target=args.target.strip(), on_progress=None)
    result = await runner.run()

    if result.get("status") != "completed":
        if args.as_json:
            print(json.dumps(result, indent=2))
        else:
            print(f"error: {result.get('error', 'pipeline failed')}", file=sys.stderr)
        return 1

    if args.as_json:
        print(json.dumps(result, indent=2))
    else:
        print(format_text(result))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(run_cli(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
