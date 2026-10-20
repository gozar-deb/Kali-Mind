"""Engagement playbook runner — load YAML playbooks and execute via orchestrator."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

import yaml

from kali_mind.agent.models import ExecutionPlan, PlanStep

logger = logging.getLogger(__name__)


def find_playbooks() -> List[Path]:
    candidates = []
    # bundled examples
    root = Path(__file__).resolve().parents[2] / "examples" / "playbooks"
    if root.exists():
        candidates.extend(sorted(root.glob("*.yaml")))
    try:
        from kali_mind.config import settings
        user_dir = settings.home_dir / "playbooks"
        if user_dir.exists():
            candidates.extend(sorted(user_dir.glob("*.yaml")))
    except Exception:
        pass
    return candidates


def load_playbook(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text()) or {}
    if "steps" not in data:
        raise ValueError(f"Playbook missing steps: {path}")
    return data


def playbook_to_plan(data: Dict[str, Any], target: str) -> ExecutionPlan:
    steps = []
    for i, s in enumerate(data.get("steps", []), 1):
        steps.append(PlanStep(
            step=i,
            description=s.get("description", f"step {i}"),
            tool=s.get("tool"),
            operation=s.get("operation"),
            target=s.get("target") or target,
            options=s.get("options") or {},
            parallel=bool(s.get("parallel", False)),
        ))
    return ExecutionPlan(
        objective=data.get("description") or data.get("name") or "playbook",
        steps=steps,
        requires_approval=True,
    )


async def run_playbook(
    name_or_path: str,
    target: str,
    orchestrator: Any,
) -> Any:
    path = Path(name_or_path)
    if not path.exists():
        # search by name
        matches = [p for p in find_playbooks() if p.stem == name_or_path or p.name == name_or_path]
        if not matches:
            raise FileNotFoundError(f"Playbook not found: {name_or_path}")
        path = matches[0]
    data = load_playbook(path)
    plan = playbook_to_plan(data, target)
    return await orchestrator.execute_plan(plan)
