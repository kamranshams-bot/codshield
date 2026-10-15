"""Write the git-native (v3) Postman collection with real saved examples.

    python tools/postman/build.py                         # v2.1 collection (the source of truth for requests)
    newman run docs/postman/CODShield.postman_collection.json -e <env> --folder ... -r json \\
        --reporter-json-export /tmp/run.json --export-environment /tmp/env-after.json
    python tools/postman/build_v3.py /tmp/run.json /tmp/env-after.json http://127.0.0.1:8000

Writes postman/collections/CODShield API/ (one YAML file per request, folder definition and example)
and postman/environments/*.yaml. Secrets in captured responses are replaced with placeholders.
"""
import json
import re
import shutil
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent))
import build  # noqa: E402  (the v2.1 definitions)

ROOT = Path(__file__).resolve().parents[2] / "postman"     # Postman's git-native directory
OUT = ROOT / "collections" / "CODShield API"
ENVS = ROOT / "environments"

SECRET_PATTERNS = [
    (re.compile(r"cs_live_[A-Za-z0-9_\-]{10,}"), "cs_live_EXAMPLEKEYdoNotUse0000000000000"),
    (re.compile(r"cs_test_[A-Za-z0-9_\-]{10,}"), "cs_test_EXAMPLEKEYdoNotUse0000000000000"),
    (re.compile(r"\bcs_(?!live_|test_)[A-Za-z0-9_\-]{20,}"), "cs_EXAMPLEoriginalStoreKey000000000000"),
    (re.compile(r"sess_[A-Za-z0-9_\-]{10,}"), "sess_EXAMPLEsessionToken000000000000"),
]
SECRET_FIELDS = {"temporary_password": "TempPass-example", "signing_secret": "whsec_EXAMPLEsigningSecret0000",
                 "token": "sess_EXAMPLEsessionToken000000000000", "api_key": "cs_live_EXAMPLEKEYdoNotUse0000000000000"}


def scrub(obj, key=None):
    if isinstance(obj, dict):
        return {k: scrub(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        items = [scrub(v) for v in obj]
        return items[:3] if len(items) > 5 else items       # long lists: keep a sample
    if isinstance(obj, str):
        if key == "prefix" and obj.startswith("cs_"):
            return obj[:8] + "abcd…"
        if key in SECRET_FIELDS and obj:
            if key == "api_key" and obj.startswith("cs_test_"):
                return "cs_test_EXAMPLEKEYdoNotUse0000000000000"
            return SECRET_FIELDS[key]
        for rx, rep in SECRET_PATTERNS:
            obj = rx.sub(rep, obj)
    return obj


def q(s: str) -> str:
    """Single-quoted YAML scalar."""
    return "'" + str(s).replace("'", "''") + "'"


def block(text: str, indent: int) -> str:
    pad = " " * indent
    return "|-\n" + "\n".join(pad + line if line else "" for line in text.splitlines())


def fname(name: str) -> str:
    return re.sub(r'[/\\:*?"<>|]', "-", name).strip().rstrip(".")


def auth_v3(a):
    if not a:
        return None
    t = a["type"]
    if t == "noauth":
        return {"type": "noauth", "credentials": []}
    return {"type": t, "credentials": [{"key": x["key"], "value": x["value"]} for x in a[t]]}


def auth_yaml(a, indent=0):
    pad = " " * indent
    if a["type"] == "noauth":
        return f"{pad}auth:\n{pad}  type: noauth\n"
    out = f"{pad}auth:\n{pad}  type: {a['type']}\n{pad}  credentials:\n"
    for c in a["credentials"]:
        out += f"{pad}    - key: {q(c['key'])}\n{pad}      value: {q(c['value'])}\n"
    return out


def trim_body(raw: str) -> str:
    """Batch bodies are 1,000 records; documentation shows three (the full files live in testdata/out/)."""
    try:
        data = json.loads(raw)
    except ValueError:
        return raw
    if isinstance(data, list) and len(data) > 5:
        data = data[:3]
    return json.dumps(data, indent=2, ensure_ascii=False)


def url_of(req):
    return req["url"]["raw"]          # includes ?query=..., kept identical to queryParams


def request_yaml(item, order, examples_dir=None):
    r = item["request"]
    lines = ["$kind: http-request"]
    stem = fname(item["name"])
    if stem != item["name"]:
        lines.append(f"name: {q(item['name'])}")
    lines += [f"method: {r['method']}", f"url: {q(url_of(r))}", f"order: {order}"]
    params = r["url"].get("query") or []
    if params:
        lines.append("queryParams:")
        lines += [f"  - key: {q(p['key'])}\n    value: {q(p['value'])}" for p in params]
    path_vars = re.findall(r"\{\{(\w+)\}\}", "/".join(r["url"]["path"]))
    if r.get("header"):
        lines.append("headers:")
        lines += [f"  - key: {q(h['key'])}\n    value: {q(h['value'])}" for h in r["header"]]
    if r.get("body"):
        lines.append("body:\n  type: json\n  content: " + block(trim_body(r["body"]["raw"]), 4))
    text = "\n".join(lines) + "\n"
    if r.get("auth"):
        text += auth_yaml(auth_v3(r["auth"]))
    scripts = [e for e in item.get("event", []) if e["listen"] == "test"]
    if scripts:
        code = "\n".join(scripts[0]["script"]["exec"])
        text += "scripts:\n  - type: afterResponse\n    language: text/javascript\n    code: " + block(code, 6) + "\n"
    if examples_dir:
        text += f"examples: {q(examples_dir)}\n"
    if path_vars:
        text += "# path variables come from the environment: " + ", ".join(path_vars) + "\n"
    return stem, text


def example_yaml(name, method, url, code, status, ctype, body, order):
    text = (f"$kind: http-example\nname: {q(name)}\norder: {order}\nrequest:\n  url: {q(url)}\n  method: {method}\n"
            f"response:\n  statusCode: {code}\n  statusText: {q(status)}\n  headers:\n"
            f"    - key: Content-Type\n      value: {q(ctype)}\n")
    if body is not None:
        text += "  body:\n    type: json\n    content: " + block(json.dumps(body, indent=2, ensure_ascii=False), 6) + "\n"
    return text


STATUS_TEXT = {200: "OK", 201: "Created", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
               404: "Not Found", 409: "Conflict", 413: "Content Too Large", 422: "Unprocessable Content",
               429: "Too Many Requests"}


def error_examples(base, env):
    """Extra failure examples for the main integration requests, captured live."""
    key, H = env.get("apiKey"), {}
    c = httpx.Client(base_url=base, timeout=30)
    H = {"X-API-Key": key}
    one = build.outcome_one
    cases = {
        "Check one customer (phone)": [
            ("401 no key", c.post("/v1/check", json={"phone": "03001234567"})),
            ("401 invalid key", c.post("/v1/check", json={"phone": "03001234567"}, headers={"X-API-Key": "cs_live_wrong"})),
            ("422 invalid country", c.post("/v1/check", json={"phone": "03001234567", "country": "IN"}, headers=H)),
            ("422 no valid identifier", c.post("/v1/check", json={"phone": "123"}, headers=H)),
        ],
        "Report one outcome": [
            ("422 unknown type", c.post("/v1/events", json=one | {"type": "fraud"}, headers=H)),
            ("422 missing fields", c.post("/v1/events", json={"phone": "03001234567"}, headers=H)),
        ],
        "Check batch (500 test customers)": [
            ("413 batch too large", c.post("/v1/check/batch", json=[{"phone": "03001234567"}] * 501, headers=H)),
        ],
    }
    return cases


def main(run_path, env_path, base):
    run = json.loads(Path(run_path).read_text())
    env = {v["key"]: v["value"] for v in json.loads(Path(env_path).read_text())["values"]}
    captured = {}
    for ex in run["run"]["executions"]:
        resp = ex.get("response")
        if not resp:
            continue
        data = bytes(resp["stream"]["data"]).decode("utf-8", "replace")
        try:
            body = json.loads(data)
        except ValueError:
            body = None
        ctype = next((h["value"] for h in resp.get("header", []) if h["key"].lower() == "content-type"), "application/json")
        captured.setdefault(ex["item"]["name"], (resp["code"], resp.get("status", ""), ctype, body))
    extra = error_examples(base, env)

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    col = build.collection
    res = OUT / ".resources"
    res.mkdir()
    variables = [("baseUrl", build.LIVE_URL)]
    (res / "definition.yaml").write_text(
        "$kind: collection\nname: CODShield API v1\ndescription: " + block(col["info"]["description"], 2) + "\n"
        + "variables:\n" + "".join(f"  - key: {k}\n    value: {q(v)}\n" for k, v in variables)
        + auth_yaml(auth_v3(col["auth"])))
    n_req = n_ex = 0
    for fi, f in enumerate(col["item"], 1):
        fdir = OUT / fname(f["name"])
        (fdir / ".resources").mkdir(parents=True)
        desc = f.get("description", "")
        reqs = "\n".join(f"- {it['name']}: {it['request'].get('description')}" for it in f["item"]
                         if it["request"].get("description"))
        if reqs:
            desc += "\n\n" + reqs
        d = f"$kind: collection\nname: {q(f['name'])}\norder: {fi * 1000}\n"
        if desc:
            d += "description: " + block(desc, 2) + "\n"
        if f.get("auth"):
            d += auth_yaml(auth_v3(f["auth"]))
        (fdir / ".resources" / "definition.yaml").write_text(d)
        for ri, it in enumerate(f["item"], 1):
            stem = fname(it["name"])
            exdir = f".resources/{stem}.resources/examples"
            examples = []
            if it["name"] in captured:
                code, status, ctype, body = captured[it["name"]]
                examples.append((f"{code} {STATUS_TEXT.get(code, status)}", code, status, ctype, body))
            for label, r in extra.get(it["name"], []):
                examples.append((label, r.status_code, STATUS_TEXT.get(r.status_code, ""), "application/json", r.json()))
            _, text = request_yaml(it, ri * 1000, f"./{exdir}/" if examples else None)
            (fdir / f"{stem}.request.yaml").write_text(text)
            n_req += 1
            if examples:
                (fdir / exdir).mkdir(parents=True)
                for ei, (label, code, status, ctype, body) in enumerate(examples, 1):
                    (fdir / exdir / f"{fname(label)}.example.yaml").write_text(
                        example_yaml(label, it["request"]["method"], url_of(it["request"]), code,
                                     STATUS_TEXT.get(code, status), ctype, scrub(body), ei * 1000))
                    n_ex += 1

    ENVS.mkdir(exist_ok=True)
    for name, base_url in (("CODShield Live", build.LIVE_URL), ("CODShield Local", "http://127.0.0.1:8000")):
        e = build.env(name, base_url)
        text = f"name: {q(name)}\nvalues:\n" + "".join(
            f"  - key: {v['key']}\n    value: {q(v['value'])}\n    enabled: true\n    type: {v['type']}\n" for v in e["values"])
        (ENVS / f"{name.split()[-1].lower()}.yaml").write_text(text)
    print(f"v3 collection: {n_req} requests, {n_ex} examples → {OUT}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
