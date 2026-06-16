"""Pipeline Engine — runs multi-phase security scans."""
import asyncio
import json
import time
from datetime import datetime
from typing import Any, Callable

from backend.config import PIPELINES, TOOLS
from backend.scanner import run_tool, run_parallel


class PipelineRunner:
    """Executes a pipeline with real-time progress callbacks."""

    def __init__(self, pipeline_id: int, mode: str, target: str,
                 on_progress: Callable | None = None):
        self.pipeline_id = pipeline_id
        self.mode = mode
        self.target = target
        self.on_progress = on_progress
        self.config = PIPELINES.get(mode)
        self.results = {}
        self.status = "pending"
        self.current_phase = ""
        self.current_tool = ""
        self.progress = 0.0
        self.start_time = None

    async def run(self) -> dict:
        """Execute all phases sequentially, tools within phases in parallel."""
        if not self.config:
            return {"error": f"Unknown pipeline mode: {self.mode}"}

        self.status = "running"
        self.start_time = time.time()
        phases = self.config["phases"]
        total_phases = len(phases)

        all_results = {}

        for i, phase in enumerate(phases):
            self.current_phase = phase["name"]
            tools = phase["tools"]
            phase_results = {}

            await self._emit({
                "type": "phase_start",
                "phase": phase["name"],
                "tools": tools,
                "progress": round((i / total_phases) * 100, 1),
            })

            # Run tools in parallel within phase
            tasks = []
            for tool_name in tools:
                self.current_tool = tool_name
                await self._emit({
                    "type": "tool_start",
                    "phase": phase["name"],
                    "tool": tool_name,
                    "tool_info": TOOLS.get(tool_name, {}),
                })
                tasks.append(self._run_single(tool_name, phase["name"]))

            results = await asyncio.gather(*tasks)

            for tool_name, result in zip(tools, results):
                phase_results[tool_name] = result
                await self._emit({
                    "type": "tool_complete",
                    "phase": phase["name"],
                    "tool": tool_name,
                    "success": result.get("success", False),
                    "elapsed": result.get("elapsed_seconds", 0),
                })

            all_results[phase["name"]] = phase_results
            self.progress = round(((i + 1) / total_phases) * 100, 1)

            await self._emit({
                "type": "phase_complete",
                "phase": phase["name"],
                "progress": self.progress,
            })

        elapsed = round(time.time() - self.start_time, 2)
        self.status = "completed"

        await self._emit({
            "type": "pipeline_complete",
            "elapsed": elapsed,
            "total_tools": sum(len(p["tools"]) for p in phases),
        })

        return {
            "mode": self.mode,
            "target": self.target,
            "status": "completed",
            "elapsed_seconds": elapsed,
            "phases": all_results,
            "total_tools": sum(len(p["tools"]) for p in phases),
        }

    async def _run_single(self, tool_name: str, phase: str) -> dict:
        """Run a single tool with timeout."""
        return await run_tool(tool_name, self.target)

    async def _emit(self, event: dict):
        """Send progress event to callback."""
        event["pipeline_id"] = self.pipeline_id
        event["timestamp"] = datetime.utcnow().isoformat()
        if self.on_progress:
            try:
                await self.on_progress(event)
            except Exception:
                pass
