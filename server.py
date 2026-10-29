#!/usr/bin/env python3
"""
cdeck — the Claude side of the CDeck Apple TV dashboard.

Your TV shows a 6-character pairing code. This MCP claims that code, keeps the
resulting push token, and lets your Claude push a "deck" (a small JSON document
of stats, lists, calendar rows and notes) that the TV renders and refreshes.

No accounts, no cloud login. The pairing code is the account. The service
behind it (cdeck-api) only ever sees the JSON your Claude chooses to push.

Tools:
  cdeck_pair(code, name)     claim the code shown on the TV
  cdeck_schema()             the deck document format + composition guidance
  cdeck_push(deck, name)     send a deck to the TV
  cdeck_status(name)         when it last updated + which items were checked off on the TV
  cdeck_list()               paired TVs on this machine
  cdeck_unpair(name)         forget a TV (server side + local)

Containment: push tokens live in ~/.config/cdeck/decks.json (0600). The only
thing a push token can do is replace the deck on one TV. There is no delete
of anything except the pairing itself.
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from mcp.server.fastmcp import FastMCP

__version__ = "0.1.0"

SERVER = os.environ.get("CDECK_SERVER", "https://cdeck.bigassmonkey.com").rstrip("/")
CONFIG_DIR = Path(os.environ.get("CDECK_CONFIG_DIR", Path.home() / ".config" / "cdeck"))
DECKS_FILE = CONFIG_DIR / "decks.json"
AUDIT_LOG = CONFIG_DIR / "audit.log"
HTTP_TIMEOUT = 20

mcp = FastMCP("cdeck")


# ----------------------------------------------------------------- plumbing

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _audit(event: str, **kw) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a") as f:
            f.write(json.dumps({"t": _now(), "event": event, **kw}) + "\n")
    except Exception:
        pass


def _load() -> dict:
    try:
        return json.loads(DECKS_FILE.read_text())
    except Exception:
        return {}


def _save(d: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = DECKS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(DECKS_FILE)


def _pick(name: str | None) -> tuple[str, dict]:
    decks = _load()
    if not decks:
        raise RuntimeError("No TV is paired yet. Look at the TV for a 6-character code and call cdeck_pair(code).")
    if name:
        if name not in decks:
            raise RuntimeError(f"No TV named {name!r}. Paired: {', '.join(decks)}")
        return name, decks[name]
    if len(decks) == 1:
        n = next(iter(decks))
        return n, decks[n]
    raise RuntimeError(f"More than one TV is paired; pass name=. Paired: {', '.join(decks)}")


def _req(method: str, path: str, token: str | None = None, body=None) -> dict:
    headers = {"accept": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    r = requests.request(method, SERVER + path, headers=headers, json=body, timeout=HTTP_TIMEOUT)
    try:
        data = r.json()
    except ValueError:
        data = {"error": r.text[:300]}
    if r.status_code >= 400:
        raise RuntimeError(f"{SERVER}{path} -> {r.status_code}: {data.get('error', data)}")
    return data


GUIDANCE = """
HOW TO COMPOSE A GOOD DECK (read this once, then just do it)

The TV is a 16:9 screen read from across a room. Think 'glanceable', not 'complete'.
  - One 'stats' section at the top: 3-5 big numbers that answer "do I need to do anything?"
  - Two or three columns below it (sections of type list/calendar/text). Two is ideal.
  - 6-10 rows per column. More scrolls; nobody scrolls on a TV.
  - Short text: subject lines, not paragraphs. Put the detail in 'meta'.
  - kind colours: hot=red (overdue/urgent), warn=amber, alert=orange, acc=blue (neutral/info), ok=green, dim=grey.

WHAT TO PUT ON IT: look at the connectors this Claude actually has and pick the two or
three streams the person acts on daily. Typical picks, in order of value:
  1. Things assigned to them with a deadline (Planner, Asana, Linear, Jira, Fathom action items).
  2. Mail/messages that need a reply and are waiting on them (Gmail, Outlook, Slack).
  3. Today's calendar.
  4. One line of status for something they run (uptime, revenue, open tickets).
Ask the person once which of these they care about; then stop asking and keep it fresh.

CHECK-OFFS: give list items a stable 'id'. When the person clicks one on the TV, cdeck_status()
returns it under 'acks'. On the next refresh, treat acked items as done in the source system
if you can (complete the Planner task, archive the thread) and drop them from the deck.

KEEPING IT FRESH: after the first push, create a recurring scheduled task (every 20-30 minutes
during waking hours is plenty) whose prompt is: gather the same streams, build the deck in this
exact shape, call cdeck_push. Set deck.refresh_seconds to match.

MINIMAL VALID DECK:
{"v":1,"updated":"<ISO-8601>","title":"Command Deck","subtitle":"<name>","refresh_seconds":1200,
 "sections":[
   {"type":"stats","items":[{"n":"3","label":"Open action items","sub":"1 overdue","kind":"hot"}]},
   {"type":"list","title":"YOUR ACTION ITEMS","width":0.6,
    "groups":[{"title":"Weekly sync · Oct 29","items":[{"id":"fathom:123","text":"Send the proposal","done":false}]}]},
   {"type":"list","title":"INBOX — NEEDS REPLY",
    "items":[{"id":"mail:abc","tag":"HOT","kind":"hot","text":"Invoice question","meta":"Jane · 2h ago"}]}
 ]}
"""


# -------------------------------------------------------------------- tools

@mcp.tool()
def cdeck_pair(code: str, name: str = "tv") -> str:
    """Pair with the Apple TV showing this 6-character code. `name` labels this TV locally
    (default 'tv'); use distinct names if you pair more than one TV."""
    code = "".join(ch for ch in code.upper() if ch.isalnum())
    if len(code) != 6:
        return "The code is 6 letters/digits, as shown on the TV."
    decks = _load()
    if name in decks:
        return f"A TV named {name!r} is already paired. Pick another name or cdeck_unpair({name!r}) first."
    data = _req("POST", "/v1/pair/claim", body={"code": code})
    decks[name] = {"push_token": data["push_token"], "paired_at": data.get("paired_at"), "server": SERVER}
    _save(decks)
    _audit("pair", name=name)
    return (f"Paired {name!r}. The TV now says 'Waiting for Claude'. "
            f"Call cdeck_schema() once, build a deck from this person's connectors, then cdeck_push(deck).")


@mcp.tool()
def cdeck_schema() -> str:
    """The deck document format (schema v1) plus guidance on what makes a good deck. Read this
    before the first push."""
    try:
        live = _req("GET", "/v1/schema")
        schema = json.dumps(live, indent=2)
    except Exception as e:  # offline: still return the guidance
        schema = f"(could not fetch live schema from {SERVER}: {e})"
    return "SCHEMA (from server)\n" + schema + "\n" + GUIDANCE


@mcp.tool()
def cdeck_push(deck: dict | str, name: str | None = None) -> str:
    """Push a deck to the paired TV. `deck` is the JSON document (object or JSON string) in the
    format from cdeck_schema(). Replaces whatever the TV is showing."""
    if isinstance(deck, str):
        try:
            deck = json.loads(deck)
        except ValueError as e:
            return f"deck is not valid JSON: {e}"
    if not isinstance(deck, dict):
        return "deck must be a JSON object."
    deck.setdefault("v", 1)
    deck.setdefault("updated", _now())
    n, rec = _pick(name)
    data = _req("PUT", "/v1/deck", token=rec["push_token"], body=deck)
    _audit("push", name=n, sections=data.get("sections"))
    return f"Pushed to {n!r}: {data.get('sections')} sections, updated {data.get('updated')}. The TV picks it up within ~{deck.get('refresh_seconds', 1200)}s or on its next Refresh."


@mcp.tool()
def cdeck_status(name: str | None = None) -> str:
    """When the TV's deck was last updated, and which item ids the viewer has checked off on
    the TV ('acks'). Use acks to complete/clear those items in their source before the next push."""
    n, rec = _pick(name)
    data = _req("GET", "/v1/status", token=rec["push_token"])
    data["name"] = n
    return json.dumps(data, indent=2)


@mcp.tool()
def cdeck_list() -> str:
    """List the TVs paired on this machine."""
    decks = _load()
    if not decks:
        return "No TVs paired. Look at the TV for a code and call cdeck_pair(code)."
    return "\n".join(f"{k}: paired {v.get('paired_at')} via {v.get('server')}" for k, v in decks.items())


@mcp.tool()
def cdeck_unpair(name: str) -> str:
    """Forget a paired TV: revokes the push token server-side and removes it locally. The TV will
    show a new pairing code."""
    decks = _load()
    if name not in decks:
        return f"No TV named {name!r}."
    try:
        _req("POST", "/v1/unpair", token=decks[name]["push_token"])
    except Exception as e:
        sys.stderr.write(f"server unpair failed ({e}); removing locally anyway\n")
    del decks[name]
    _save(decks)
    _audit("unpair", name=name)
    return f"Unpaired {name!r}."


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in ("-V", "--version"):
        print(f"cdeck-mcp {__version__}")
        return
    mcp.run()


if __name__ == "__main__":
    main()
