"""Runs against a live cdeck-api (default localhost:8787). CDECK_SERVER overrides.
Python plays the TV here: generates the TV keypair, pairs, and decrypts what the MCP pushed."""
import json, os, tempfile, urllib.request as u, base64, hmac, hashlib
os.environ.setdefault("CDECK_SERVER", "http://localhost:8787")
os.environ["CDECK_CONFIG_DIR"] = tempfile.mkdtemp()
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import server as s

def call(m, p, tok=None, body=None):
    h = {"content-type": "application/json"}
    if tok: h["authorization"] = "Bearer " + tok
    r = u.Request(s.SERVER + p, method=m, data=json.dumps(body).encode() if body is not None else None, headers=h)
    try:
        with u.urlopen(r) as x: return x.status, json.loads(x.read())
    except u.HTTPError as e: return e.code, json.loads(e.read())

class FakeTV:
    def __init__(self):
        self.sk = X25519PrivateKey.generate()
        pk = self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        st, n = call("POST", "/v1/pair/new", body={"pk": base64.b64encode(pk).decode(), "name": "pytv"})
        assert st == 200, n
        self.code, self.tok = n["code"], n["device_token"]
    def keys(self, peer_pk_b64):
        shared = self.sk.exchange(X25519PublicKey.from_public_bytes(base64.b64decode(peer_pk_b64)))
        aes = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"cdeck-v1-aes").derive(shared)
        mac = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"cdeck-v1-hmac").derive(shared)
        return aes, mac
    def fetch(self):
        st, e = call("GET", "/v1/deck", self.tok); assert st == 200, e
        env = e["deck"]
        if not env: return None, e
        aes, mac = self.keys(env["pk"])
        pt = AESGCM(aes).decrypt(base64.b64decode(env["nonce"]), base64.b64decode(env["ct"]), None)
        self._mac = mac
        return json.loads(pt), e
    def ack(self, item_id):
        tag = base64.b64encode(hmac.new(self._mac, item_id.encode(), hashlib.sha256).digest()).decode()
        st, r = call("POST", "/v1/ack", self.tok, {"id": tag}); assert st == 200, r
        return tag

def test_flow():
    tv = FakeTV()
    assert s.cdeck_pair("bad").startswith("The code is 6")
    assert s.cdeck_pair("zzzzzz", name="x").startswith("Pairing failed")
    assert s.cdeck_pair(tv.code, name="t1").startswith("Paired 't1'")
    assert "t1" in s.cdeck_list() and "NOT ENCRYPTED" not in s.cdeck_list()
    assert "LIMITS" in s.cdeck_schema()
    assert s.cdeck_push({"v": 1, "sections": [{"type": "nope"}]}).startswith("Push refused")
    deck = {"v": 1, "title": "T", "sections": [{"type": "list", "items": [{"id": "a", "text": "A"}, {"id": "b", "text": "B"}]}]}
    assert "(encrypted)" in s.cdeck_push(json.dumps(deck))
    # plaintext rejected by the server
    rec = s._load()["t1"]
    st, r = call("PUT", "/v1/deck", rec["push_token"], deck); assert st == 422 and "plaintext" in r["error"]
    # TV decrypts what the MCP pushed
    pt, env = tv.fetch()
    assert pt["title"] == "T" and pt["sections"][0]["items"][1]["text"] == "B"
    assert len(env["deck"]["ids"]) == 2 and env["acks"] == []
    # TV acks 'a' by tag; MCP status names it
    tag = tv.ack("a")
    st = json.loads(s.cdeck_status()); assert st["encrypted"] and list(st["acks"]) == ["a"]
    pt, env = tv.fetch(); assert env["acks"] == [tag]
    # push without 'a' clears its ack
    s.cdeck_push({"v": 1, "sections": [{"type": "list", "items": [{"id": "b", "text": "B"}]}]})
    assert json.loads(s.cdeck_status())["acks"] == {}
    # ack with non-tag rejected
    st, r = call("POST", "/v1/ack", tv.tok, {"id": "a"}); assert st == 400
    assert s.cdeck_unpair("t1") == "Unpaired 't1'."
    assert s.cdeck_list().startswith("No TVs")

def test_demo_decrypts():
    tv = FakeTV()
    st, r = call("POST", "/v1/pair/demo", body={"code": tv.code}); assert st == 200 and r["demo"], r
    pt, env = tv.fetch()
    assert env["demo"] is True and pt["sections"][0]["type"] == "stats" and "Demo" in pt["subtitle"]
    tv.ack("demo:1")
    pt, env = tv.fetch(); assert len(env["acks"]) == 1

def test_tampered_ct_fails():
    tv = FakeTV()
    s.cdeck_pair(tv.code, name="t2")
    s.cdeck_push({"v": 1, "sections": [{"type": "text", "text": "secret"}]})
    st, e = call("GET", "/v1/deck", tv.tok)
    env = e["deck"]; ct = bytearray(base64.b64decode(env["ct"])); ct[0] ^= 1
    aes, _ = tv.keys(env["pk"])
    try:
        AESGCM(aes).decrypt(base64.b64decode(env["nonce"]), bytes(ct), None); assert False, "tamper not detected"
    except Exception as ex:
        assert "tamper" not in str(ex)  # InvalidTag
    s.cdeck_unpair("t2")
