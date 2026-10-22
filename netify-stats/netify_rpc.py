#!/usr/bin/python3
import json
from contextlib import closing
import os
import sqlite3
import sys
import time

sys.path.insert(0, "/usr/lib/netify-stats")
from netify_classify import Classifier
from netify_storage import save_limit, footprint, read_settings_snapshot
from netify_control import set_enabled, control_status
from netify_query import aggregate, empty_classification_coverage, normalize_filters
from netify_accounting import interface_choices, save_interface
from netify_update import read_status, start_check, start_install

VERSION = "0.3.0"


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
    identification, search, application = normalize_filters(
        params.get('identification'), params.get('search'), params.get('application'))
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
    config = read_settings_snapshot()
    control = control_status(config['enabled'])
    control['config_error'] = config['config_error']
    selected = config['interface']
    response = {
        "version": VERSION,
        "enabled": config['enabled'],
        "config_error": config['config_error'],
        "control": control,
        "update": read_status(VERSION),
        "rules_revision": classifier.rules.get("revision", ""),
        "rules_error": classifier.error,
        "rules_sources": classifier.rules.get("sources", []),
        "hours": hours,
        "device": device,
        "identification": identification,
        "search": search,
        "application": application,
        "generated_at": now,
        "range_start": start,
        "range_end": now,
        "clock_anomaly": False,
        "clock_warning": "",
        "resolution_seconds": 3600,
        "collector": load_json(COLLECTOR_STATUS),
        "total": {"upload": 0, "download": 0, "flows": 0},
        "classification_coverage": empty_classification_coverage(),
        "timeline": [],
        "devices": [],
        "applications": [],
        "hosts": [],
        "interfaces": [],
        "interface_choices": interface_choices(),
        "selected_interface": selected,
        "active_interfaces": [selected] if selected else [],
        "storage": dict(footprint(DB_PATH), max_storage_mib=config['max_storage_mib'],
                        error=config['storage_error']),
    }
    if not os.path.exists(DB_PATH):
        return response
    # A failed classifier/query must release its read snapshot immediately too,
    # otherwise retained tracebacks can keep WAL pages pinned indefinitely.
    with closing(sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=10)) as db:
        db.row_factory = sqlite3.Row
        if identification or search or application:
            # Temporary selection keys spill to SQLite's temporary storage;
            # the bounded page cache does not grow with the full result size.
            db.execute('PRAGMA temp_store=FILE')
        db.execute("BEGIN")  # All totals and drill-downs share a consistent snapshot.
        table = 'hourly_data' if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='hourly_data'").fetchone() else 'hourly'
        has_interfaces = bool(db.execute("SELECT 1 FROM sqlite_master WHERE name='interface_hourly'").fetchone())
        tables = [table] + (['interface_hourly'] if has_interfaces else [])
        newest = max((db.execute('SELECT MAX(bucket) FROM '+name).fetchone()[0] or 0
                      for name in tables), default=0)
        current_bucket = now//3600*3600
        response['clock_anomaly'] = newest > current_bucket
        if response['clock_anomaly']:
            response['clock_warning'] = 'Retained records extend beyond the current system time.'
        if not hours:
            oldest = [db.execute('SELECT MIN(bucket) FROM '+name).fetchone()[0] for name in tables]
            response['range_start'] = min((value for value in oldest if value is not None), default=now)
            response['range_end'] = max(now, newest)
        end = current_bucket if hours else None
        if has_interfaces:
            where = 'bucket >= ?' + (' AND bucket <= ?' if end is not None else '')
            args = [start] + ([end] if end is not None else [])
            response['interfaces'] = [dict(row) for row in db.execute('''
                SELECT name, SUM(download) download, SUM(upload) upload,
                       MIN(since) since, MAX(until) until, SUM(resets) resets
                FROM interface_hourly WHERE '''+where+' GROUP BY name ORDER BY name', args)]
        latest_ips = {}
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='device_latest'").fetchone():
            latest_ips = dict(db.execute('SELECT mac, ip FROM device_latest'))
        response.update(aggregate(db, start, device, now, classifier, names, latest_ips,
                                  app_page, device_page, sort, direction, expanded, end=end,
                                  identification=identification, search=search, application=application))
    return response


def main():
    if len(sys.argv) < 2:
        return 1
    if sys.argv[1] == "list":
        print(json.dumps({"summary": {"hours": 0, "device": "", "app_page": 0, "device_page": 0, "sort": "", "direction": "", "expanded": "", "identification": "", "search": "", "application": ""}, "set_interface": {"interface": ""}, "set_storage": {"max_storage_mib": 0}, "set_enabled": {"enabled": False}, "check_update": {}, "install_update": {"version": ""}}, separators=(",", ":")))
        return 0
    if sys.argv[1] == 'call' and len(sys.argv) >= 3 and sys.argv[2] in ('check_update', 'install_update'):
        try:
            params = json.load(sys.stdin)
        except (ValueError, TypeError):
            params = {}
        version = params.get('version') if isinstance(params, dict) else None
        result = start_check(VERSION) if sys.argv[2] == 'check_update' else start_install(VERSION, version)
        print(json.dumps(result, separators=(',', ':')))
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
