"""Headless CLI — run a pipeline or a single tool from the terminal.

Usage:
    python -m backend.cli --target example.com --pipeline fast
    python -m backend.cli --tool dns_recon --target example.com
    python -m backend.cli --json --tool ssl_analyzer --target example.com
    python -m backend.cli --tool hash_checker --target d41d8cd98f00b2...
    python -m backend.cli --list-tools
    python -m backend.cli --list-pipelines

Pure headless by design: no web, no DB writes. Use the web UI for runs that
must be persisted and comparable in History.

--list-tools / --list-pipelines are informational: they take precedence over
any other action and need no --target. For special tools (hash_checker,
password_audit, cve_search, system tools) --target is the raw input, exactly
as in the web UI; only pipeline runs validate it as a host.
"""
import argparse
import asyncio
import json
import sys

from backend import scanner
from backend.config import CATEGORIES, PIPELINES, TOOLS
from backend.pipeline import PipelineRunner
from backend.validators import validate_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="backend.cli",
        description="Run a security pipeline or single tool headless (no web, no DB).",
    )
    parser.add_argument("--target",
                        help="Target host (e.g. example.com); raw input for special tools")
    parser.add_argument("--pipeline", default=None, choices=sorted(PIPELINES),
                        help="Pipeline mode (default: fast)")
    parser.add_argument("--tool",
                        help="Run a single tool by id instead of a pipeline (see --list-tools)")
    list_group = parser.add_mutually_exclusive_group()
    list_group.add_argument("--list-tools", action="store_true",
                            help="List available tools and exit")
    list_group.add_argument("--list-pipelines", action="store_true",
                            help="List pipeline modes, phases and their tools, and exit")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Print the full result as JSON instead of a text summary")
    return parser


def _resolve_action(parser: argparse.ArgumentParser, args: argparse.Namespace) -> str:
    """Validate flag combinations and pick the effective action.

    Returns one of: list_tools, list_pipelines, tool, pipeline.
    List actions are informational and take precedence over the rest.
    Usage errors go through parser.error (exit code 2).
    """
    if args.list_tools:
        return "list_tools"
    if args.list_pipelines:
        return "list_pipelines"
    if args.tool is not None and args.pipeline is not None:
        parser.error("--tool and --pipeline are mutually exclusive")
    if args.tool is not None:
        if args.tool not in scanner.HANDLERS:
            parser.error(f"unknown tool: {args.tool} (see --list-tools)")
        if args.target is None:
            parser.error("--tool requires --target")
        return "tool"
    if args.target is None:
        parser.error("the following arguments are required: --target")
    return "pipeline"


def _table(header: tuple[str, ...], rows: list[tuple]) -> str:
    """Render rows as an aligned text table (one row per line)."""
    widths = [max(len(h), *(len(str(r[i])) for r in rows)) for i, h in enumerate(header)]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(header)).rstrip()]
    for row in rows:
        lines.append("  ".join(str(v).ljust(widths[i]) for i, v in enumerate(row)).rstrip())
    return "\n".join(lines)


def format_tools_list() -> str:
    """All registered tools, sorted by category (registry order) then name."""
    order = {c: i for i, c in enumerate(CATEGORIES)}
    items = sorted(TOOLS.items(),
                   key=lambda kv: (order.get(kv[1]["category"], len(order)), kv[1]["name"]))
    rows = [(tid, cfg["name"], cfg["category"], cfg["description"]) for tid, cfg in items]
    return _table(("ID", "NAME", "CATEGORY", "DESCRIPTION"), rows)


def format_pipelines_list() -> str:
    """One row per phase: mode | phase | tools."""
    rows = [(mode, phase["name"], ", ".join(phase["tools"]))
            for mode, cfg in PIPELINES.items()
            for phase in cfg["phases"]]
    return _table(("MODE", "PHASE", "TOOLS"), rows)


def format_tool_text(result: dict) -> str:
    """One-screen human summary of a single tool result."""
    lines = [
        f"tool: {result.get('tool')}",
        f"target: {result.get('target')}",
        "status: ok",
        f"elapsed: {result.get('elapsed_seconds')}s",
        f"findings: {len(result.get('findings', []))}",
        f"score: {result.get('score')}",
    ]
    return "\n".join(lines)


async def run_tool_cli(args: argparse.Namespace) -> int:
    result = await scanner.run_tool(args.tool, args.target.strip())
    if not result.get("success"):
        if args.as_json:
            print(json.dumps(result, indent=2))
        else:
            print(f"error: {result.get('error', 'tool failed')}", file=sys.stderr)
        return 1
    if args.as_json:
        print(json.dumps(result, indent=2))
    else:
        print(format_tool_text(result))
    return 0


async def run_pipeline_cli(args: argparse.Namespace) -> int:
    ok, reason = validate_target(args.target)
    if not ok:
        print(f"error: invalid target: {reason}", file=sys.stderr)
        return 1

    runner = PipelineRunner(pipeline_id=0, mode=args.pipeline or "fast",
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
        print("\n".join(lines))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    action = _resolve_action(parser, args)
    if action == "list_tools":
        print(format_tools_list())
        return 0
    if action == "list_pipelines":
        print(format_pipelines_list())
        return 0
    coro = run_tool_cli(args) if action == "tool" else run_pipeline_cli(args)
    try:
        return asyncio.run(coro)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
