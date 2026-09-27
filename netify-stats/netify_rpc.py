#!/usr/bin/python3
import json
from contextlib import closing
import os
import sqlite3
import sys
import time

sys.path.insert(0, "/usr/lib/netify-stats")
from netify_classify import Classifier
from netify_storage import save_limit, settings, read_enabled
from netify_control import set_enabled, control_status
from netify_query import aggregate
from netify_accounting import interface_choices, selected_interface, save_interface, active_interfaces

VERSION = "0.2.8"


DB_PATH = "/tmp/netify-stats/stats.db"
COLLECTOR_STATUS = "/var/run/netify-stats/status.json"
NETIFY_STATUS = "/var/run/netifyd/status.json"


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def device_names():
    names = {}
    try:
        with open("/tmp/dhcp.leases", "r", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 4:
                    mac, ip, name = fields[1].lower(), fields[2], fields[3]
                    if name != "*":
                        names[mac] = name
                        names[ip] = name
    except OSError:
        pass
    return names


def pretty_app(value):
    value = value or "Unknown"
    if value.startswith("netify."):
        value = value[7:]
    return value.replace("-", " ").replace("/", " / ").title()


def query_summary(params):
    if not isinstance(params, dict):
        params = {}
    try:
        hours = int(params.get("hours", 0))
    except (TypeError, ValueError, OverflowError):
        hours = 24
    hours = max(hours, 0)  # Zero means all retained data from this boot.
    device = str(params.get("device") or "").lower()
    now = int(time.time())
    # Include the boundary bucket rather than silently dropping its traffic.
    start = max(0, ((now - hours * 3600) // 3600) * 3600) if hours else 0
    names = device_names()
    classifier = Classifier()
    def page_value(key):
        try:
            return max(1, min(100000, int(params.get(key) or 1)))
        except (ValueError, TypeError, OverflowError):
            return 1
    app_page, device_page = page_value('app_page'), page_value('device_page')
    sort = params.get('sort') if params.get('sort') in ('total','upload','download','flows') else 'total'
    direction = 'asc' if params.get('direction') == 'asc' else 'desc'
    expanded = params.get('expanded') or '[]'
    try:
        expanded = json.loads(expanded)
        expanded = [v for v in expanded if isinstance(v, str)][:10] if isinstance(expanded, list) else []
    except (ValueError, TypeError):
        expanded = []
    response = {
        "version": VERSION,
        "enabled": read_enabled(),
        "control": control_status(),
        "rules_revision": classifier.rules.get("revision", ""),
        "rules_error": classifier.error,
        "rules_sources": classifier.rules.get("sources", []),
        "hours": hours,
        "device": device,
        "generated_at": now,
        "range_start": start,
        "resolution_seconds": 3600,
        "collector": load_json(COLLECTOR_STATUS),
        "total": {"upload": 0, "download": 0, "flows": 0},
        "timeline": [],
        "devices": [],
        "applications": [],
        "hosts": [],
        "interfaces": [],
        "interface_choices": interface_choices(),
        "selected_interface": selected_interface(),
        "active_interfaces": active_interfaces(),
        "storage": settings(DB_PATH),
    }
    if not os.path.exists(DB_PATH):
        return response
    # A failed classifier/query must release its read snapshot immediately too,
    # otherwise retained tracebacks can keep WAL pages pinned indefinitely.
    with closing(sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=10)) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")  # All totals and drill-downs share a consistent snapshot.
        if not hours:
            oldest = db.execute('SELECT MIN(bucket) FROM hourly').fetchone()[0]
            response['range_start'] = oldest if oldest is not None else now
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='interface_hourly'").fetchone():
            response['interfaces'] = [dict(row) for row in db.execute('''
                SELECT name, SUM(download) download, SUM(upload) upload,
                       MIN(since) since, MAX(until) until, SUM(resets) resets
                FROM interface_hourly WHERE bucket >= ? GROUP BY name ORDER BY name''', (start,))]
        latest_ips = {}
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='device_latest'").fetchone():
            latest_ips = dict(db.execute('SELECT mac, ip FROM device_latest'))
        response.update(aggregate(db, start, device, now, classifier, names, latest_ips,
                                  app_page, device_page, sort, direction, expanded))
    return response


def main():
    if len(sys.argv) < 2:
        return 1
    if sys.argv[1] == "list":
        print(json.dumps({"summary": {"hours": 0, "device": "", "app_page": 0, "device_page": 0, "sort": "", "direction": "", "expanded": ""}, "set_interface": {"interface": ""}, "set_storage": {"max_storage_mib": 0}, "set_enabled": {"enabled": False}}, separators=(",", ":")))
        return 0
    if sys.argv[1] == 'call' and len(sys.argv) >= 3 and sys.argv[2] == 'set_interface':
        try:
            result = save_interface(json.load(sys.stdin).get('interface'))
        except (ValueError, TypeError, AttributeError, OSError) as exc:
            result = {'error': str(exc)}
        print(json.dumps(result))
        return 0
    if sys.argv[1] == 'call' and len(sys.argv) >= 3 and sys.argv[2] == 'set_enabled':
        try:
            result = set_enabled(json.load(sys.stdin).get('enabled'))
        except Exception as exc:
            result = {'error':str(exc), 'control': control_status()}
        print(json.dumps(result))
        return 0
    if sys.argv[1] == 'call' and len(sys.argv) >= 3 and sys.argv[2] == 'set_storage':
        try:
            params = json.load(sys.stdin)
            result = save_limit(params.get('max_storage_mib'))
        except (ValueError, TypeError, AttributeError, OSError) as exc:
            result = {'error': str(exc)}
        print(json.dumps(result))
        return 0
    if sys.argv[1] == "call" and len(sys.argv) >= 3 and sys.argv[2] == "summary":
        try:
            params = json.load(sys.stdin)
        except Exception:
            params = {}
        print(json.dumps(query_summary(params), separators=(",", ":")))
        return 0
    print(json.dumps({"error": "unknown_method"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
