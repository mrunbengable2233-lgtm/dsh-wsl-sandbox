#!/usr/bin/env python3
"""Lightweight Trellis task manager for dsh-wsl-sandbox."""
import argparse
import datetime
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TRELLIS_DIR = ROOT / ".trellis"
TASKS_DIR = TRELLIS_DIR / "tasks"
CURRENT_FILE = TRELLIS_DIR / ".current-task"


def slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower()).strip("-")
    return s[:48] or "task"


def cmd_create(args):
    TASKS_DIR.mkdir(parents=True, exist_ok=True)
    today = datetime.date.today().strftime("%m-%d")
    slug = slugify(args.title if args.slug == "auto" else args.slug)
    task_name = f"{today}-{slug}"
    task_dir = TASKS_DIR / task_name
    task_dir.mkdir(parents=True, exist_ok=True)
    (task_dir / "research").mkdir(exist_ok=True)

    meta = {
        "name": task_name,
        "title": args.title,
        "description": args.description or "",
        "status": "planning",
        "parent": args.parent,
        "subtasks": [],
        "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    (task_dir / "task.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    prd = task_dir / "prd.md"
    if not prd.exists():
        prd.write_text(f"# {args.title}\n\n## Goal\n{args.description or ''}\n", encoding="utf-8")

    if args.parent:
        parent_meta_path = Path(args.parent) / "task.json"
        if not parent_meta_path.is_absolute():
            parent_meta_path = ROOT / parent_meta_path
        if parent_meta_path.exists():
            pmeta = json.loads(parent_meta_path.read_text(encoding="utf-8"))
            pmeta.setdefault("subtasks", [])
            if task_name not in pmeta["subtasks"]:
                pmeta["subtasks"].append(task_name)
            parent_meta_path.write_text(json.dumps(pmeta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    CURRENT_FILE.write_text(str(task_dir.relative_to(ROOT)) + "\n", encoding="utf-8")
    print(str(task_dir.relative_to(ROOT)))


def cmd_current(_args):
    if CURRENT_FILE.exists():
        print(CURRENT_FILE.read_text(encoding="utf-8").strip())
    else:
        print("", end="")


def cmd_start(args):
    target = Path(args.task) if args.task else (ROOT / CURRENT_FILE.read_text(encoding="utf-8").strip())
    if not target.is_absolute():
        target = ROOT / target
    meta_path = target / "task.json"
    if not meta_path.exists():
        sys.exit(f"Task metadata not found: {meta_path}")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["status"] = "in_progress"
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    CURRENT_FILE.write_text(str(target.relative_to(ROOT)) + "\n", encoding="utf-8")
    print(f"Started {target.relative_to(ROOT)}")


def cmd_archive(args):
    src = TASKS_DIR / args.task
    if not src.exists():
        src = ROOT / args.task
    if not src.exists():
        sys.exit(f"Task not found: {args.task}")
    arch_root = TASKS_DIR / "archive"
    arch_root.mkdir(parents=True, exist_ok=True)
    dst = arch_root / src.name
    meta_path = src / "task.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["status"] = "archived"
        meta["archivedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    shutil.move(str(src), str(dst))
    if CURRENT_FILE.exists() and CURRENT_FILE.read_text(encoding="utf-8").strip().endswith(src.name):
        CURRENT_FILE.unlink()
    print(f"Archived to {dst.relative_to(ROOT)}")


def main():
    parser = argparse.ArgumentParser(description="Trellis task manager")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create")
    p_create.add_argument("title")
    p_create.add_argument("--description", default="")
    p_create.add_argument("--slug", default="auto")
    p_create.add_argument("--parent", default=None)
    p_create.set_defaults(func=cmd_create)

    p_cur = sub.add_parser("current")
    p_cur.set_defaults(func=cmd_current)

    p_start = sub.add_parser("start")
    p_start.add_argument("task", nargs="?")
    p_start.set_defaults(func=cmd_start)

    p_arch = sub.add_parser("archive")
    p_arch.add_argument("task")
    p_arch.set_defaults(func=cmd_archive)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
