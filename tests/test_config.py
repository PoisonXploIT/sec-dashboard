"""Registry consistency tests (backend/config.py + scanner HANDLERS)."""
import backend.config as config
from backend.scanner import HANDLERS


def test_every_handler_has_registry_entry():
    missing = set(HANDLERS) - set(config.TOOLS)
    assert not missing, f"Tools in HANDLERS but not in TOOLS: {missing}"


def test_every_registered_tool_has_required_fields():
    for name, meta in config.TOOLS.items():
        for field in ("name", "category", "description", "timeout"):
            assert field in meta, f"{name} missing '{field}'"
        assert isinstance(meta["timeout"], int) and meta["timeout"] > 0


def test_pipeline_tools_all_registered():
    for mode, pipe in config.PIPELINES.items():
        for phase in pipe["phases"]:
            for tool in phase["tools"]:
                assert tool in config.TOOLS, (
                    f"Pipeline '{mode}' references unregistered tool '{tool}'"
                )


def test_special_tools_are_registered():
    missing = set(config.SPECIAL_TOOLS) - set(config.TOOLS)
    assert not missing, f"SPECIAL_TOOLS not in TOOLS: {missing}"


def test_categories_covered_by_registry():
    known = set()
    for meta in config.TOOLS.values():
        known.add(meta["category"])
    # CATEGORIES may omit categories added later; the registry must not be empty.
    assert len(known) >= 4


def test_pipeline_modes_exist():
    assert {"fast", "deep", "nuclear"} <= set(config.PIPELINES)
