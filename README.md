# cdeck-mcp

The Claude side of **[CDeck](https://github.com/SuperAngryMonkey/CDeck)**, an Apple TV dashboard that your own Claude keeps up to date.

No accounts. The 6-character code on your TV is the account.

## Setup (three steps)

1. Install **CDeck** on your Apple TV. It shows a code.
2. Add this MCP to Claude (Claude Desktop → Settings → Connectors → Add, or in `claude_desktop_config.json`):
   ```json
   { "mcpServers": { "cdeck": { "command": "uvx", "args": ["cdeck-mcp"] } } }
   ```
3. Tell Claude: **"Pair my Command Deck, code ABC123."**

Claude calls `cdeck_pair`, reads `cdeck_schema`, looks at whatever connectors *you* have (Gmail, Outlook, Planner, Fathom, Linear, …), builds a deck, pushes it, and sets up a recurring scheduled task to keep it fresh. The TV polls the feed on the interval the deck asks for.

## Tools

| tool | does |
|---|---|
| `cdeck_pair(code, name="tv")` | claim the code on the TV |
| `cdeck_schema()` | deck format + how to compose a good one |
| `cdeck_push(deck, name=None)` | replace what the TV shows |
| `cdeck_status(name=None)` | last update + items you checked off on the TV |
| `cdeck_list()` | paired TVs |
| `cdeck_unpair(name)` | forget a TV |

## Deck format (v1)

```json
{"v":1,"updated":"2026-10-29T20:00:00Z","title":"Command Deck","subtitle":"Jane · Acme",
 "refresh_seconds":1200,
 "sections":[
   {"type":"stats","items":[{"n":"3","label":"Open action items","sub":"1 overdue","kind":"hot"}]},
   {"type":"list","title":"YOUR ACTION ITEMS","width":0.6,
    "groups":[{"title":"Weekly sync · Oct 29","items":[{"id":"fathom:123","text":"Send the proposal"}]}]},
   {"type":"list","title":"INBOX — NEEDS REPLY",
    "items":[{"id":"mail:abc","tag":"HOT","kind":"hot","text":"Invoice question","meta":"Jane · 2h ago"}]},
   {"type":"calendar","title":"TODAY","items":[{"time":"2:00 PM","text":"Vendor call","meta":"Zoom"}]},
   {"type":"text","title":"NOTES","text":"Anything else worth a glance."}
 ]}
```

`stats` renders as a tile row; every other section becomes a column. Items with an `id` get a checkbox on the TV; checked ids come back in `cdeck_status()` so Claude can complete them at the source.

## Self-hosting

The service is a single Cloudflare Worker + KV namespace (`api/` in the [CDeck repo](https://github.com/SuperAngryMonkey/CDeck)). Deploy it, set `CDECK_SERVER`, and rebuild the TV app with your URL in `project.yml`.

## Privacy

The hosted service stores: a random device token, a random push token, and the last deck JSON your Claude pushed. Nothing else. `cdeck_unpair` deletes all of it.

MIT · 800 Pound Gorilla Inc.
