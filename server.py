#!/usr/bin/env python3
"""
cdeck — the Claude side of the CDeck Apple TV dashboard.

Your TV shows a 6-character pairing code. This MCP claims that code, keeps the
resulting push token, and lets your Claude push a "deck" (a small JSON document
of stats, lists, calendar rows and notes) that the TV renders and refreshes.

No accounts, no cloud login. The pairing code is the account. Decks are
END-TO-END ENCRYPTED: on pairing this MCP receives the TV's X25519 public key,
generates its own keypair, and every push is AES-256-GCM sealed here before it
leaves the machine. The relay (cdeck-api) stores ciphertext it has no key for.
Check-off ids travel as HMAC tags, so even those are opaque to the relay.

Tools:
  cdeck_pair(code, name)     claim the code shown on the TV
  cdeck_schema()             the deck document format + composition guidance
  cdeck_push(deck, name)     send a deck to the TV
  cdeck_status(name)         when it last updated + which items were checked off on the TV
  cdeck_list()               paired TVs on this machine
  cdeck_unpair(name)         forget a TV (server side + local)

Containment: push tokens and the per-TV private key live in
~/.config/cdeck/decks.json (0600). The only thing a push token can do is
replace the deck on one TV. Losing decks.json means re-pairing (the TV shows a
new code from its gear menu); nothing on the relay is recoverable without it.
"""
import base64
import hashlib
import hmac as _hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from mcp.server.fastmcp import FastMCP

__version__ = "0.2.0"

SERVER = os.environ.get("CDECK_SERVER", "https://cdeck.happymonkey.dev").rstrip("/")
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


# ------------------------------------------------------------------ crypto

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _derive(sk_b64: str, tv_pk_b64: str) -> tuple[bytes, bytes]:
    """shared = X25519(sk_mcp, pk_tv); aes/hmac keys via HKDF-SHA256 (matches the TV + Worker)."""
    sk = X25519PrivateKey.from_private_bytes(_b64d(sk_b64))
    pk = X25519PublicKey.from_public_bytes(_b64d(tv_pk_b64))
    shared = sk.exchange(pk)
    aes = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"cdeck-v1-aes").derive(shared)
    mac = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"cdeck-v1-hmac").derive(shared)
    return aes, mac


def _tag(mac_key: bytes, item_id: str) -> str:
    return _b64e(_hmac.new(mac_key, item_id.encode(), hashlib.sha256).digest())


def _seal(rec: dict, deck: dict) -> dict:
    aes, mac = _derive(rec["sk"], rec["tv_pk"])
    nonce = os.urandom(12)
    ct = AESGCM(aes).encrypt(nonce, json.dumps(deck, separators=(",", ":")).encode(), None)
    ids = []
    for sec in deck.get("sections", []):
        items = list(sec.get("items") or []) + [it for g in (sec.get("groups") or []) for it in (g.get("items") or [])]
        for it in items:
            if isinstance(it, dict) and it.get("id"):
                ids.append(_tag(mac, str(it["id"])))
    rec["last_ids"] = {t: i for t, i in zip(ids, _plain_ids(deck))}
    return {"v": 2, "pk": rec["pk"], "nonce": _b64e(nonce), "ct": _b64e(ct), "ids": ids, "updated": deck.get("updated")}


def _plain_ids(deck: dict) -> list[str]:
    out = []
    for sec in deck.get("sections", []):
        items = list(sec.get("items") or []) + [it for g in (sec.get("groups") or []) for it in (g.get("items") or [])]
        for it in items:
            if isinstance(it, dict) and it.get("id"):
                out.append(str(it["id"]))
    return out


# Local plaintext validation (mirrors the limits the old server enforced; the
# server can no longer see the deck, so this is the only check).
LIMITS = {"sections": 8, "rows": 60, "stats": 6, "str": 300, "text": 2000}
_TYPES = {"stats", "list", "calendar", "text"}


def _validate(d) -> str | None:
    if not isinstance(d, dict):
        return "deck must be an object"
    if d.get("v") != 1:
        return "deck.v must be 1"
    secs = d.get("sections")
    if not isinstance(secs, list):
        return "deck.sections must be an array"
    if len(secs) > LIMITS["sections"]:
        return f"at most {LIMITS['sections']} sections"
    for k in ("title", "subtitle", "updated"):
        v = d.get(k)
        if v is not None and (not isinstance(v, str) or len(v) > LIMITS["str"]):
            return f"deck.{k} must be a string of at most {LIMITS['str']} chars"
    rs = d.get("refresh_seconds")
    if rs is not None and (not isinstance(rs, (int, float)) or not 60 <= rs <= 86400):
        return "refresh_seconds must be 60..86400"
    rows = 0

    def chk(it, where):
        nonlocal rows
        if not isinstance(it, dict):
            return f"{where} must be an object"
        for k in ("id", "text", "n", "label", "sub", "kind", "tag", "meta", "time"):
            v = it.get(k)
            if v is not None and (not isinstance(v, str) or len(v) > LIMITS["str"]):
                return f"{where}.{k} must be a string of at most {LIMITS['str']} chars"
        rows += 1
        return None

    for i, s in enumerate(secs):
        w = f"sections[{i}]"
        if not isinstance(s, dict) or s.get("type") not in _TYPES:
            return f"{w}.type must be one of {', '.join(sorted(_TYPES))}"
        if s.get("type") == "text":
            if not isinstance(s.get("text"), str) or len(s["text"]) > LIMITS["text"]:
                return f"{w}.text must be a string of at most {LIMITS['text']} chars"
            continue
        if s.get("type") == "stats" and len(s.get("items") or []) > LIMITS["stats"]:
            return f"{w}: at most {LIMITS['stats']} stats"
        if s.get("type") == "list" and not isinstance(s.get("items"), list) and not isinstance(s.get("groups"), list):
            return f"{w} needs items or groups"
        if s.get("type") in ("stats", "calendar") and not isinstance(s.get("items"), list):
            return f"{w}.items required"
        for j, g in enumerate(s.get("groups") or []):
            if not isinstance(g, dict) or not isinstance(g.get("items"), list):
                return f"{w}.groups[{j}].items required"
            for k, it in enumerate(g["items"]):
                e = chk(it, f"{w}.groups[{j}].items[{k}]")
                if e:
                    return e
        for k, it in enumerate(s.get("items") or []):
            e = chk(it, f"{w}.items[{k}]")
            if e:
                return e
    if rows > LIMITS["rows"]:
        return f"at most {LIMITS['rows']} rows across all sections (got {rows})"
    return None


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
if you can (complete the Planner task, archive the thread) and drop them from the deck. The TV
keeps an acked item struck through until a push omits it, so nothing "un-checks" on refresh.

LIMITS (server enforces, 422 on violation): 8 sections, 60 rows total, 6 stats, strings 300 chars,
text sections 2000 chars, refresh_seconds 60..86400, width 0..1.

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
    try:
        data = _req("POST", "/v1/pair/claim", body={"code": code})
    except RuntimeError as e:
        return f"Pairing failed: {e}"
    if not data.get("tv_pk"):
        return "Pairing failed: the TV did not provide an encryption key (app too old? needs CDeck >= 2.1)."
    sk = X25519PrivateKey.generate()
    decks[name] = {
        "push_token": data["push_token"],
        "paired_at": data.get("paired_at"),
        "server": SERVER,
        "tv_pk": data["tv_pk"],
        "sk": _b64e(sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())),
        "pk": _b64e(sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
    }
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
    bad = _validate(deck)
    if bad:
        return f"Push refused: {bad}. Fix the deck and try again (cdeck_schema() has the limits)."
    n, rec = _pick(name)
    if "sk" not in rec:
        return f"TV {n!r} was paired before encryption was added. cdeck_unpair({n!r}) and pair again."
    env = _seal(rec, deck)
    try:
        data = _req("PUT", "/v1/deck", token=rec["push_token"], body=env)
    except RuntimeError as e:
        return f"Push refused: {e}."
    decks = _load(); decks[n] = rec; _save(decks)   # persist last_ids so status can name acks
    _audit("push", name=n, sections=len(deck["sections"]))
    return f"Pushed to {n!r} (encrypted): {len(deck['sections'])} sections, updated {data.get('updated')}. The TV picks it up within ~{deck.get('refresh_seconds', 1200)}s or on its next Refresh."


@mcp.tool()
def cdeck_status(name: str | None = None) -> str:
    """When the TV's deck was last updated, and which item ids the viewer has checked off on
    the TV ('acks'). Use acks to complete/clear those items in their source before the next push."""
    n, rec = _pick(name)
    data = _req("GET", "/v1/status", token=rec["push_token"])
    data["name"] = n
    # Server acks are HMAC tags; map back to the ids from the last push.
    last = rec.get("last_ids") or {}
    data["acks"] = {last.get(t, f"<unknown tag {t[:8]}…>"): when for t, when in (data.get("acks") or {}).items()}
    data["encrypted"] = True
    return json.dumps(data, indent=2)


@mcp.tool()
def cdeck_list() -> str:
    """List the TVs paired on this machine."""
    decks = _load()
    if not decks:
        return "No TVs paired. Look at the TV for a code and call cdeck_pair(code)."
    return "\n".join(f"{k}: paired {v.get('paired_at')} via {v.get('server')}" + ("" if v.get("sk") else "  [NOT ENCRYPTED — unpair + re-pair]") for k, v in decks.items())


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
