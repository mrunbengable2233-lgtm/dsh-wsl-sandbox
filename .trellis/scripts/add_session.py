#!/usr/bin/env python3
"""Record developer session progress into .trellis/workspace/."""
import argparse
import datetime
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_DIR = ROOT / ".trellis" / "workspace" / os.environ.get("USER", "dev")


def main():
    parser = argparse.ArgumentParser(description="Append a Trellis session journal entry")
    parser.add_argument("--title", required=True)
    parser.add_argument("--commit", default="")
    parser.add_argument("--summary", required=True)
    args = parser.parse_args()

    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    journal = WORKSPACE_DIR / "journal.md"
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    entry = (
        f"\n## {now} — {args.title}\n"
        f"- **Commits**: `{args.commit or 'uncommitted'}`\n"
        f"- **Summary**: {args.summary}\n"
    )
    if not journal.exists():
        journal.write_text("# Session Journal\n" + entry, encoding="utf-8")
    else:
        with journal.open("a", encoding="utf-8") as fh:
            fh.write(entry)
    print(f"Recorded journal entry in {journal.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
