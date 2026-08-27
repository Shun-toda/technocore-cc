#!/usr/bin/env python3
"""Fail when the English original has moved and the Japanese translation has not.

A translation is a second copy, and a second copy drifts. The upstream project says
so about its own documents, and it is right: `/llms.txt` grew 18% in the 24 hours
after this translation was started. So the translation does not get to claim it is
current — it gets checked.

Each entry in `PINS` records the SHA-256 of the English document the translation was
made from. This fetches the live document, compares, and exits non-zero on a
difference. That is the whole contract: it does not try to judge whether the change
was material, because a script cannot, and a translation whose freshness is a
judgement call is the thing being avoided.

When it fails: read the diff, update the translation, then re-pin with --update.

Usage:
    python scripts/check_docs_drift.py            # check, exit 1 on drift
    python scripts/check_docs_drift.py --update   # re-pin after translating
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import urllib.error
import urllib.request

BASE = "https://technocore.chat"
PINS = pathlib.Path(__file__).resolve().parent.parent / "docs" / "ja" / "pins.json"
UA = "technocore-cc-docs-drift/1.0 (+https://github.com/Shun-toda/technocore-cc)"

# English original -> the translation that tracks it.
TRACKED = {
    "/llms.txt": "docs/ja/llms.ja.md",
    "/skill.md": "docs/ja/skill.ja.md",
}


def fetch(path: str) -> str:
    request = urllib.request.Request(BASE + path, headers={"User-Agent": UA})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_pins() -> dict[str, dict[str, str]]:
    try:
        return json.loads(PINS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--update", action="store_true",
        help="re-pin to what upstream serves now; run only after updating the translation",
    )
    args = parser.parse_args()

    pins = load_pins()
    drifted, fresh = [], {}

    for path, translation in TRACKED.items():
        try:
            body = fetch(path)
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"?? {path}: could not fetch ({exc}) — not treated as drift")
            fresh[path] = pins.get(path, {})
            continue
        now = digest(body)
        pinned = pins.get(path, {}).get("sha256")
        fresh[path] = {"sha256": now, "bytes": len(body.encode("utf-8")), "tracked_by": translation}
        if pinned is None:
            print(f"++ {path}: no pin yet ({translation})")
            drifted.append(path)
        elif pinned != now:
            was = pins[path].get("bytes", "?")
            print(
                f"!! {path}: upstream moved — pinned {pinned[:12]} ({was} bytes), "
                f"now {now[:12]} ({len(body.encode('utf-8'))} bytes). Update {translation}."
            )
            drifted.append(path)
        else:
            print(f"ok {path}: unchanged since {translation} was written")

    if args.update:
        PINS.write_text(json.dumps(fresh, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nre-pinned {len(fresh)} document(s) in {PINS.name}")
        return 0

    if drifted:
        print(f"\n{len(drifted)} document(s) drifted. The translations are stale until updated.")
        return 1
    print("\nall translations track their originals")
    return 0


if __name__ == "__main__":
    sys.exit(main())
