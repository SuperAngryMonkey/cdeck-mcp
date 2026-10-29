"""Runs against a live cdeck-api (default localhost:8787). CDECK_SERVER overrides."""
import json, os, tempfile, urllib.request as u
os.environ.setdefault("CDECK_SERVER", "http://localhost:8787")
os.environ["CDECK_CONFIG_DIR"] = tempfile.mkdtemp()
import server as s

def new_code():
    r = u.Request(s.SERVER + "/v1/pair/new", method="POST", data=b"{}", headers={"content-type": "application/json"})
    with u.urlopen(r) as x: return json.loads(x.read())

def test_flow():
    n = new_code()
    assert s.cdeck_pair("bad").startswith("The code is 6")
    assert s.cdeck_pair("zzzzzz", name="x").startswith("Pairing failed")
    assert s.cdeck_pair(n["code"], name="t1").startswith("Paired 't1'")
    assert "t1" in s.cdeck_list()
    assert "LIMITS" in s.cdeck_schema()
    assert s.cdeck_push({"v": 1, "sections": [{"type": "nope"}]}).startswith("Push refused")
    assert "Pushed to 't1'" in s.cdeck_push(json.dumps({"v": 1, "sections": [{"type": "list", "items": [{"id": "a", "text": "A"}]}]}))
    st = json.loads(s.cdeck_status())
    assert st["paired"] and st["sections"] == 1 and st["acks"] == {}
    # ack from the TV side, then status sees it
    r = u.Request(s.SERVER + "/v1/ack", method="POST", data=b'{"id":"a"}', headers={"content-type": "application/json", "authorization": "Bearer " + n["device_token"]})
    u.urlopen(r).read()
    assert "a" in json.loads(s.cdeck_status())["acks"]
    assert s.cdeck_unpair("t1") == "Unpaired 't1'."
    assert s.cdeck_list().startswith("No TVs")
    assert s.cdeck_unpair("t1").startswith("No TV named")
