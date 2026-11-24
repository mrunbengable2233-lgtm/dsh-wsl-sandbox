#!/usr/bin/env python3
"""Lightweight Trellis context inspector for dsh-wsl-sandbox."""
import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TRELLIS_DIR = ROOT / ".trellis"


def run_git(args):
    try:
        res = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return res.stdout.strip() if res.returncode == 0 else "(not a git repo yet)"
    except Exception:
        return "(git unavailable)"


def list_packages():
    spec_root = TRELLIS_DIR / "spec"
    if not spec_root.exists():
        print("No .trellis/spec directory found.")
        return
    print("=== Spec Layers (.trellis/spec) ===")
    for p in sorted(spec_root.iterdir()):
        if p.is_dir():
            files = sorted(f.name for f in p.glob("*.md"))
            print(f"- {p.name}/: {', '.join(files) if files else '(empty)'}")


def show_phase(step=None):
    wf = TRELLIS_DIR / "workflow.md"
    if not wf.exists():
        print("Missing .trellis/workflow.md")
        return
    text = wf.read_text(encoding="utf-8")
    if step:
        print(f"=== Workflow Focus (step {step}) ===")
    print(text)


def read_tasks():
    tasks_dir = TRELLIS_DIR / "tasks"
    active, archived = [], []
    if tasks_dir.exists():
        for entry in sorted(tasks_dir.iterdir()):
            if entry.is_dir() and entry.name != "archive":
                meta_file = entry / "task.json"
                meta = json.loads(meta_file.read_text(encoding="utf-8")) if meta_file.exists() else {}
                active.append({"dir": entry.name, **meta})
        arch_dir = tasks_dir / "archive"
        if arch_dir.exists():
            archived = sorted(p.name for p in arch_dir.iterdir() if p.is_dir())
    return active, archived


def show_status(record_mode=False):
    current_file = TRELLIS_DIR / ".current-task"
    current = current_file.read_text(encoding="utf-8").strip() if current_file.exists() else "(none)"
    active, archived = read_tasks()
    print(f"Workspace root: {ROOT}")
    print(f"Developer: {os.environ.get('USER', 'dev')}")
    print(f"Current task: {current}")
    print("Active tasks:")
    if not active:
        print("  (none)")
    for t in active:
        print(f"  - {t['dir']} [{t.get('status', 'unknown')}]: {t.get('title', '')}")
    if archived:
        print(f"Archived tasks: {len(archived)}")
    print("\nGit status:")
    print(run_git(["status", "--short"]) or "(clean)")
    if record_mode:
        print("\nRecent commits:")
        print(run_git(["log", "--oneline", "-n", "10"]))


def main():
    parser = argparse.ArgumentParser(description="Trellis context helper")
    parser.add_argument("--mode", choices=["status", "packages", "phase", "record"], default="status")
    parser.add_argument("--step", default=None)
    args = parser.parse_args()

    if args.mode == "packages":
        list_packages()
    elif args.mode == "phase":
        show_phase(args.step)
    elif args.mode == "record":
        show_status(record_mode=True)
    else:
        show_status(record_mode=False)


if __name__ == "__main__":
    main()
