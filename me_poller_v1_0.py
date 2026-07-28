#!/usr/bin/env python3
"""
me_poller.py  --  v1.0
N&R SOLARTECH  |  Micro-Energy  |  Tuya -> Supabase poller

WHAT IT DOES (one run):
  1. For each configured Tuya project: get an access token
  2. Read every meter in me_meters, ask Tuya for its current status
  3. Scale the raw values to real units and insert a row in me_meter_samples
  4. Update me_meters.last_seen / last_online
  5. Execute any pending rows in me_commands (relay_on / relay_off / refresh)
     and log the result in me_relay_events

Designed to run once a day from GitHub Actions. No server, no gateway box.
Works across several Tuya projects at once, because the bench meters live in
the Singapore project and production lives in Western America.

ENVIRONMENT
  SUPABASE_URL          https://sdviemivuftnsytmnqaq.supabase.co
  SUPABASE_SERVICE_KEY  service_role key (server-side only, never in the portal)
  TUYA_PROJECTS         JSON array, e.g.
    [
      {"name":"bench",
       "host":"https://openapi-sg.iotbing.com",
       "access_id":"...","access_secret":"..."},
      {"name":"production",
       "host":"https://openapi.tuyaus.com",
       "access_id":"...","access_secret":"..."}
    ]

TUYA REGION HOSTS
  China          https://openapi.tuyacn.com
  Western America https://openapi.tuyaus.com
  Eastern America https://openapi-ueaz.tuyaus.com
  Central Europe  https://openapi.tuyaeu.com
  Western Europe  https://openapi-weaz.tuyaeu.com
  India           https://openapi.tuyain.com
  Singapore       https://openapi-sg.iotbing.com

USAGE
  python me_poller.py              # normal run
  python me_poller.py --selftest   # no network: check scaling against a
                                   # known bench sample and exit
  python me_poller.py --dry-run    # read from Tuya, print, write nothing
"""

import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime, timezone

import urllib.request
import urllib.error

VERSION = "1.0"

# ---------------------------------------------------------------------------
# scaling - confirmed 28 Jul 2026 against the app and the physical meter
# ---------------------------------------------------------------------------

SCALE = {
    "voltage": 10.0,     # -> V
    "current": 1000.0,   # -> A
    "power": 10.0,       # -> W
    "fac": 100.0,        # -> power factor
    "fre": 1.0,          # -> Hz
    "temp": 1.0,         # -> degC
    "run_time": 1.0,     # -> minutes
}


def scale_status(status_list):
    """Turn Tuya's [{code,value}, ...] into a scaled dict for me_meter_samples."""
    dp = {item["code"]: item["value"] for item in status_list}

    def num(code):
        v = dp.get(code)
        if v is None or isinstance(v, bool):
            return None
        try:
            return float(v) / SCALE.get(code, 1.0)
        except (TypeError, ValueError):
            return None

    def raw_int(code):
        v = dp.get(code)
        if v is None or isinstance(v, bool):
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    online = dp.get("online_state")
    return {
        "switch_on": dp.get("switch"),
        "online": None if online is None else (online == "online"),
        "voltage_v": num("voltage"),
        "current_a": num("current"),
        "power_w": num("power"),
        "power_factor": num("fac"),
        "frequency_hz": num("fre"),
        "temp_c": raw_int("temp"),
        "run_time_min": raw_int("run_time"),
        "energy_raw": raw_int("energy"),
        "add_ele_raw": raw_int("add_ele"),
        "raw": dp,
    }


# ---------------------------------------------------------------------------
# tiny HTTP helper
# ---------------------------------------------------------------------------

def http(method, url, headers=None, body=None, timeout=30):
    data = None
    if body is not None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else None)
    except urllib.error.HTTPError as e:
        text = e.read().decode()
        try:
            return e.code, json.loads(text)
        except json.JSONDecodeError:
            return e.code, {"error": text}


# ---------------------------------------------------------------------------
# Tuya
# ---------------------------------------------------------------------------

class Tuya:
    """Minimal Tuya OpenAPI client. HMAC-SHA256 signing, no dependencies."""

    def __init__(self, name, host, access_id, access_secret):
        self.name = name
        self.host = host.rstrip("/")
        self.access_id = access_id
        self.access_secret = access_secret
        self.token = None

    @staticmethod
    def _sha256(body):
        return hashlib.sha256((body or "").encode()).hexdigest()

    def _sign(self, str_to_sign):
        return hmac.new(
            self.access_secret.encode(), str_to_sign.encode(), hashlib.sha256
        ).hexdigest().upper()

    def _headers(self, method, path, body="", with_token=True):
        t = str(int(time.time() * 1000))
        string_to_sign = "\n".join([method, self._sha256(body), "", path])
        token = self.token if with_token else ""
        sign = self._sign(self.access_id + token + t + string_to_sign)
        h = {
            "client_id": self.access_id,
            "sign": sign,
            "t": t,
            "sign_method": "HMAC-SHA256",
            "Content-Type": "application/json",
        }
        if with_token:
            h["access_token"] = token
        return h

    def connect(self):
        path = "/v1.0/token?grant_type=1"
        status, data = http("GET", self.host + path,
                            self._headers("GET", path, "", with_token=False))
        if not data or not data.get("success"):
            raise RuntimeError(f"[{self.name}] token failed: {status} {data}")
        self.token = data["result"]["access_token"]
        return self

    def get(self, path):
        status, data = http("GET", self.host + path, self._headers("GET", path))
        return data

    def post(self, path, body_obj):
        body = json.dumps(body_obj, separators=(",", ":"))
        status, data = http("POST", self.host + path,
                            self._headers("POST", path, body), body)
        return data

    def device_status(self, device_ids):
        """Bulk status. Falls back to one-by-one if the bulk call is rejected."""
        ids = ",".join(device_ids)
        data = self.get(f"/v1.0/iot-03/devices/status?device_ids={ids}")
        if data and data.get("success"):
            return {d["id"]: d["status"] for d in data["result"]}

        out = {}
        for dev in device_ids:
            d = self.get(f"/v1.0/iot-03/devices/status?device_ids={dev}")
            if d and d.get("success") and d.get("result"):
                out[dev] = d["result"][0]["status"]
        return out

    def send_switch(self, device_id, on):
        return self.post(
            f"/v1.0/iot-03/devices/{device_id}/commands",
            {"commands": [{"code": "switch", "value": bool(on)}]},
        )


# ---------------------------------------------------------------------------
# Supabase (PostgREST)
# ---------------------------------------------------------------------------

class Supabase:
    def __init__(self, url, key):
        self.url = url.rstrip("/")
        self.key = key

    def _h(self, extra=None):
        h = {
            "apikey": self.key,
            "Authorization": "Bearer " + self.key,
            "Content-Type": "application/json",
        }
        h.update(extra or {})
        return h

    def select(self, table, query=""):
        status, data = http("GET", f"{self.url}/rest/v1/{table}?{query}", self._h())
        if status >= 300:
            raise RuntimeError(f"select {table} failed: {status} {data}")
        return data or []

    def insert(self, table, rows):
        if not rows:
            return
        status, data = http("POST", f"{self.url}/rest/v1/{table}", 
                            self._h({"Prefer": "return=minimal"}), rows)
        if status >= 300:
            raise RuntimeError(f"insert {table} failed: {status} {data}")

    def update(self, table, query, patch):
        status, data = http("PATCH", f"{self.url}/rest/v1/{table}?{query}",
                            self._h({"Prefer": "return=minimal"}), patch)
        if status >= 300:
            raise RuntimeError(f"update {table} failed: {status} {data}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def selftest():
    """Check the scaler against the real bench reading from 28 Jul 2026."""
    sample = [
        {"code": "switch", "value": True},
        {"code": "voltage", "value": 2223},
        {"code": "current", "value": 71},
        {"code": "power", "value": 97},
        {"code": "run_time", "value": 1480},
        {"code": "energy", "value": 1670},
        {"code": "fac", "value": 61},
        {"code": "fre", "value": 60},
        {"code": "temp", "value": -20},
        {"code": "add_ele", "value": 8545},
    ]
    got = scale_status(sample)
    expect = {
        "voltage_v": 222.3, "current_a": 0.071, "power_w": 9.7,
        "power_factor": 0.61, "frequency_hz": 60.0, "temp_c": -20,
        "run_time_min": 1480, "energy_raw": 1670, "add_ele_raw": 8545,
        "switch_on": True,
    }
    ok = True
    for k, want in expect.items():
        have = got[k]
        good = abs(have - want) < 1e-6 if isinstance(want, float) else have == want
        print(f"  {'ok ' if good else 'FAIL'} {k:<14} {have!r:<12} expected {want!r}")
        ok = ok and good

    va = got["voltage_v"] * got["current_a"]
    print(f"\n  cross-check: {got['voltage_v']} V x {got['current_a']} A = "
          f"{va:.2f} VA x {got['power_factor']} PF = {va * got['power_factor']:.2f} W "
          f"(meter reported {got['power_w']} W)")
    print("\nselftest:", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main():
    dry = "--dry-run" in sys.argv
    print(f"me_poller v{VERSION}  {datetime.now(timezone.utc).isoformat()}"
          f"{'  [DRY RUN]' if dry else ''}")

    sb = Supabase(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_KEY"])
    projects = json.loads(os.environ["TUYA_PROJECTS"])

    meters = sb.select(
        "me_meters",
        "select=id,device_id,label,is_active,energy_field,energy_divisor&is_active=eq.true",
    )
    if not meters:
        print("no active meters in me_meters - nothing to do")
        return 0
    by_device = {m["device_id"]: m for m in meters}
    print(f"{len(meters)} active meter(s) in me_meters")

    pending = sb.select(
        "me_commands",
        "select=id,meter_id,action,reason&status=eq.pending&order=requested_at.asc",
    )
    if pending:
        print(f"{len(pending)} pending command(s)")

    seen = set()
    now = datetime.now(timezone.utc).isoformat()

    for cfg in projects:
        try:
            tuya = Tuya(cfg["name"], cfg["host"],
                        cfg["access_id"], cfg["access_secret"]).connect()
        except Exception as exc:                      # noqa: BLE001
            print(f"  [{cfg['name']}] SKIPPED - {exc}")
            continue

        wanted = [d for d in by_device if d not in seen]
        if not wanted:
            continue

        statuses = tuya.device_status(wanted)
        print(f"  [{cfg['name']}] {len(statuses)} of {len(wanted)} device(s) answered")

        rows = []
        for device_id, status_list in statuses.items():
            seen.add(device_id)
            meter = by_device[device_id]
            vals = scale_status(status_list)
            counter = (vals["energy_raw"] if meter["energy_field"] == "energy"
                       else vals["add_ele_raw"])
            kwh = (counter / float(meter["energy_divisor"])) if counter is not None else None
            print(f"    {meter['label']:<18} {vals['voltage_v']} V  "
                  f"{vals['power_w']} W  counter {counter} "
                  f"({kwh} kWh)  switch={vals['switch_on']}")

            rows.append({
                "meter_id": meter["id"],
                "taken_at": now,
                "online": True if vals["online"] is None else vals["online"],
                "switch_on": vals["switch_on"],
                "voltage_v": vals["voltage_v"],
                "current_a": vals["current_a"],
                "power_w": vals["power_w"],
                "power_factor": vals["power_factor"],
                "frequency_hz": vals["frequency_hz"],
                "temp_c": vals["temp_c"],
                "run_time_min": vals["run_time_min"],
                "energy_raw": vals["energy_raw"],
                "add_ele_raw": vals["add_ele_raw"],
                "raw": vals["raw"],
            })

            if not dry:
                sb.update("me_meters", f"id=eq.{meter['id']}",
                          {"last_seen": now, "last_online": True})

        if rows and not dry:
            sb.insert("me_meter_samples", rows)

        # ---- commands, only for meters this project could reach ----
        for cmd in pending:
            meter = next((m for m in meters if m["id"] == cmd["meter_id"]), None)
            if not meter or meter["device_id"] not in statuses:
                continue
            if cmd["action"] == "refresh":
                result, ok = "refreshed", True
            else:
                on = cmd["action"] == "relay_on"
                resp = tuya.send_switch(meter["device_id"], on)
                ok = bool(resp and resp.get("success"))
                result = json.dumps(resp)[:400]
                if ok and not dry:
                    sb.insert("me_relay_events", [{
                        "meter_id": meter["id"],
                        "new_state": on,
                        "reason": cmd.get("reason") or "manual",
                        "command_id": cmd["id"],
                    }])
            print(f"    command {cmd['action']} on {meter['label']}: "
                  f"{'done' if ok else 'FAILED'}")
            if not dry:
                sb.update("me_commands", f"id=eq.{cmd['id']}", {
                    "status": "done" if ok else "failed",
                    "executed_at": datetime.now(timezone.utc).isoformat(),
                    "result": result,
                })

    missing = [by_device[d]["label"] for d in by_device if d not in seen]
    if missing:
        print(f"  no answer from: {', '.join(missing)}")
        if not dry:
            for d in by_device:
                if d not in seen:
                    sb.update("me_meters", f"id=eq.{by_device[d]['id']}",
                              {"last_online": False})

    print("done")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main())
