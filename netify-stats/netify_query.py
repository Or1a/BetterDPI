"""Aggregate compact SQLite dimensions before classifying application groups."""
from copy import copy
from heapq import nsmallest

from netify_classify import APP_NAME_MSGIDS


# Search the small set of names translated by the built-in UI without loading
# translation catalogs or changing the factual label returned by the API.
_TRADITIONAL_APP_NAMES = {
    'tencent': '騰訊', 'huawei': '華為', 'bilibili': '嗶哩嗶哩',
    'jd': '京東', 'taobao': '淘寶',
}
SEARCH_APP_ALIASES = {
    tag: (english.casefold(), _TRADITIONAL_APP_NAMES.get(tag, ''))
    for tag, english in APP_NAME_MSGIDS.items()
}


def _add(target, upload, download, flows):
    target['upload'] += upload
    target['download'] += download
    target['flows'] += flows


def _counts(**labels):
    return dict(upload=0, download=0, flows=0, **labels)


def empty_classification_coverage():
    return {level: _counts() for level in ('application', 'domain', 'protocol', 'unknown')}


def normalize_filters(identification='', search='', application=''):
    identification = identification if identification in ('application', 'domain', 'protocol', 'unknown') else ''
    search = search.strip()[:128] if isinstance(search, str) else ''
    application = application.strip()[:512] if isinstance(application, str) else ''
    return identification, search, application


def aggregate(db, start, device, now, classifier, names, latest_ips,
              app_page, device_page, sort_key, direction, expanded, end=None,
              identification='', search='', application=''):
    identification, search, application = normalize_filters(identification, search, application)
    filtered = bool(identification or search or application)
    try:
        return _aggregate(db, start, device, now, classifier, names, latest_ips,
                          app_page, device_page, sort_key, direction, expanded, end,
                          identification, search, application, filtered)
    finally:
        if filtered:
            db.execute('DROP TABLE IF EXISTS temp.netify_selected_groups')


def _aggregate(db, start, device, now, classifier, names, latest_ips,
               app_page, device_page, sort_key, direction, expanded, end,
               identification, search, application, filtered):
    normalized = bool(db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='hourly_data'").fetchone())
    host_ids = normalized and any(row[1] == 'host_id' for row in
                                 db.execute('PRAGMA table_info(hourly_data)'))
    device_labels = dict((key, (mac, ip)) for key, mac, ip in db.execute(
        'SELECT id,mac,ip FROM traffic_devices')) if normalized else {}
    native_labels = dict(db.execute('SELECT id,value FROM traffic_apps')) if normalized else {}
    protocol_labels = dict(db.execute('SELECT id,value FROM traffic_protocols')) if normalized else {}
    table = 'hourly_data' if normalized else 'hourly'
    native_column = 'app_id' if normalized else 'application'
    protocol_column = 'protocol_id' if normalized else 'protocol'
    host_column = 'host_id' if host_ids else 'host'
    args = [start]
    where = 'bucket >= ?'
    if end is not None:
        where += ' AND bucket <= ?'
        args.append(end)
    if device:
        if normalized:
            # Resolve in SQLite so a device with many historical IPv6 addresses
            # cannot exceed the SQL parameter limit.
            where += ' AND device_id IN (SELECT id FROM traffic_devices WHERE mac=? OR ip=?)'
            args.extend((device, device))
        else:
            where += ' AND (mac=? OR ip=?)'
            args.extend((device, device))
    sums = 'SUM(upload),SUM(download),SUM(flows)'
    device_columns = 'device_id' if normalized else 'mac,ip'
    apps, devices = {}, {}
    total = _counts()
    hour_totals = {}

    requested = set(expanded)
    detail_hosts, detail_members = {}, {}
    coverage = empty_classification_coverage()
    selector = classifier
    if search:
        # Selection must not leak evidence from rejected hosts into a visible
        # application. Share the immutable rules and domain lookup cache, but
        # record visible evidence only in the original classifier. A matching
        # group is classified again from that cache, never per hourly record.
        selector = copy(classifier)
        selector.app_sources, selector.app_evidence = {}, {}
        selector.evidence_truncated, selector._fallbacks = set(), {}
        selector._last_unresolved, selector._last_raw_host = (None, None), None
    search_key, label_matches = search.casefold(), {}
    pending_keys = []
    matched_groups = rejected_groups = 0
    if filtered:
        # A local scratch index avoids retaining a large Python membership set
        # or constructing an IN clause beyond SQLite's parameter limit. New
        # compact data uses only integer keys. Legacy nullable dimensions need
        # a rowid table and NULL-safe comparisons instead of a WITHOUT ROWID PK.
        db.execute('PRAGMA temp.cache_size=-256')
        # Matching column affinities let SQLite use this primary key directly
        # instead of rebuilding membership data or scanning the scratch table.
        key_types = ('INTEGER', 'INTEGER', 'INTEGER') if host_ids else (
            ('INTEGER', 'INTEGER', 'TEXT') if normalized else ('TEXT', 'TEXT', 'TEXT'))
        db.execute(('CREATE TEMP TABLE netify_selected_groups ('
                    'native_key %s,protocol_key %s,host_key %s,'
                    'PRIMARY KEY(native_key,protocol_key,host_key))' % key_types)
                   + (' WITHOUT ROWID' if host_ids else ''))

    def matches(app, host):
        if identification and selector.identification_level(app) != identification:
            return False
        if application and app != application:
            return False
        if not search_key or (isinstance(host, str) and search_key in host.casefold()):
            return True
        if search_key in app.casefold():
            return True
        # Domain labels are their IDs without the prefix; formatting them
        # cannot create another match. Keep application-label reuse bounded
        # even when the input contains many distinct native application names.
        if app.startswith('domain:'):
            return False
        if app in label_matches:
            return label_matches[app]
        aliases = SEARCH_APP_ALIASES.get(app.removeprefix('community:'), ()) if app.startswith('community:') else ()
        matched = (search_key in selector.describe(app)[0].casefold()
                   or any(search_key in alias for alias in aliases))
        if len(label_matches) < 1024:
            label_matches[app] = matched
        return matched
    if host_ids:
        # Aggregate integer dimensions first, then look up only the hostnames
        # represented in this result. Never load the full host dictionary into
        # Python or rejoin a long domain string for every retained hourly row.
        app_sql = '''SELECT grouped.app_id,grouped.protocol_id,grouped.host_id,hosts.value,
            grouped.upload,grouped.download,grouped.flows FROM (
                SELECT app_id,protocol_id,host_id,SUM(upload) upload,SUM(download) download,SUM(flows) flows
                FROM hourly_data WHERE %s GROUP BY app_id,host_id,protocol_id
            ) grouped JOIN traffic_hosts hosts ON hosts.id=grouped.host_id''' % where
    else:
        app_sql = 'SELECT %s,%s,host,host,%s FROM %s WHERE %s GROUP BY %s,host,%s' % (
            native_column, protocol_column, sums, table, where, native_column, protocol_column)
    for native_key, protocol_key, host_key, host, upload, download, flows in db.execute(app_sql, args):
        native = native_labels[native_key] if normalized else native_key
        protocol = protocol_labels[protocol_key] if normalized else protocol_key
        app = selector.classify(native, host, protocol)
        if filtered:
            if not matches(app, host):
                rejected_groups += 1
                continue
            matched_groups += 1
            pending_keys.append((native_key, protocol_key, host_key))
            if len(pending_keys) == 256:
                db.executemany('INSERT INTO temp.netify_selected_groups VALUES (?,?,?)', pending_keys)
                pending_keys.clear()
            if search:
                classifier.classify(native, host, protocol)
        if app not in apps:
            apps[app] = _counts(id=app, identification_level=classifier.identification_level(app))
        _add(apps[app], upload, download, flows)
        if app in requested:
            detail_members[(native_key, protocol_key, host_key)] = app
            if host and host.lower() != 'unknown':
                hosts = detail_hosts.setdefault(app, {})
                if host not in hosts:
                    hosts[host] = _counts(name=host)
                _add(hosts[host], upload, download, flows)

    if filtered:
        if pending_keys:
            db.executemany('INSERT INTO temp.netify_selected_groups VALUES (?,?,?)', pending_keys)
        if not matched_groups:
            where += ' AND 0'
        elif not rejected_groups:
            # Every group in the already time/device-limited query matched.
            # Rechecking membership per retained record adds no information.
            pass
        else:
            where += (' AND EXISTS (SELECT 1 FROM temp.netify_selected_groups selected WHERE '
                      'selected.native_key IS %s.%s AND selected.protocol_key IS %s.%s '
                      'AND selected.host_key IS %s.%s)') % (
                          table, native_column, table, protocol_column, table, host_column)

    # One grouping supplies device totals and the timeline. The time-leading
    # primary key serves whole-network reads; schema 3's device-leading index
    # lets SQLite restrict a single-device read before aggregating its hours.
    for row in db.execute('SELECT bucket,%s,%s FROM %s WHERE %s GROUP BY bucket,%s' %
                          (device_columns, sums, table, where, device_columns), args):
        if normalized:
            bucket, key, upload, download, flows = row
            mac, ip = device_labels[key]
        else:
            bucket, mac, ip, upload, download, flows = row
        if mac not in devices:
            devices[mac] = _counts(mac=mac, ip=ip)
        else:
            devices[mac]['ip'] = max(devices[mac]['ip'], ip)
        _add(devices[mac], upload, download, flows)
        _add(total, upload, download, flows)
        hour = hour_totals.setdefault(bucket, [0, 0])
        hour[0] += upload
        hour[1] += download

    # Reuse completed application aggregates before pagination, rather than
    # incrementing coverage again for every host/protocol row. This is tiny for
    # the common case of many IPs collapsing to a few protocol-only groups.
    for app in apps.values():
        _add(coverage[app['identification_level']], app['upload'], app['download'], app['flows'])

    def order(item, identity):
        metric = item['upload']+item['download'] if sort_key == 'total' else item[sort_key]
        return (metric if direction == 'asc' else -metric, item[identity])

    app_page = min(app_page, max(1, (len(apps)+9)//10))
    device_page = min(device_page, max(1, (len(devices)+9)//10))
    app_rows = nsmallest(app_page*10, apps.values(), key=lambda x: order(x,'id'))[(app_page-1)*10:]
    device_rows = nsmallest(device_page*10, devices.values(), key=lambda x: order(x,'mac'))[(device_page-1)*10:]

    def label_device(item):
        item['ip'] = latest_ips.get(item['mac'], item['ip'])
        item['name'] = names.get(item['mac'], names.get(item['ip'], item['ip'] or item['mac']))

    for item in device_rows:
        label_device(item)
    for item in app_rows:
        item['name'], item['source'] = classifier.describe(item['id'])
        item.update(classifier.describe_metadata(item['id']))
        item['hosts'], item['devices'] = [], []

    # Application/site totals were already grouped across hours above. Expanded
    # rows need only their per-device grouping; classification is reused from
    # the selected native/protocol/host combinations instead of rerun for every
    # record. The protocol dimension matters when domain/app evidence is absent.
    selected = {row['id']:row for row in app_rows if row['id'] in expanded}
    if selected:
        app_devices = {key:{} for key in selected}
        native_keys = sorted({key[0] for key, app in detail_members.items() if app in selected})
        detail_where = where+' AND '+native_column+' IN (%s)' % ','.join('?' for _ in native_keys)
        detail_columns = device_columns+','+native_column+','+protocol_column+','+host_column
        sql = 'SELECT %s,%s FROM %s WHERE %s GROUP BY %s' % (
            detail_columns, sums, table, detail_where, detail_columns)
        for row in db.execute(sql, args+native_keys):
            if normalized:
                key, native_key, protocol_key, host_key, upload, download, flows = row
                mac, ip = device_labels[key]
            else:
                mac, ip, native_key, protocol_key, host_key, upload, download, flows = row
            app = detail_members.get((native_key, protocol_key, host_key))
            if app not in selected:
                continue
            if mac not in app_devices[app]:
                app_devices[app][mac] = _counts(mac=mac, ip=ip)
            else:
                app_devices[app][mac]['ip'] = max(app_devices[app][mac]['ip'], ip)
            _add(app_devices[app][mac], upload, download, flows)
        for app, row in selected.items():
            row['hosts'] = nsmallest(5, detail_hosts.get(app, {}).values(), key=lambda x:(-x['upload']-x['download'],x['name']))
            row['devices'] = sorted(app_devices[app].values(), key=lambda x:(-x['upload']-x['download'],x['mac']))
            for item in row['devices']:
                label_device(item)

    hours = [(bucket, *values) for bucket, values in sorted(hour_totals.items())]
    first = hours[0][0] if hours else now//3600*3600
    # A wall-clock correction can leave retained buckets ahead of now. An
    # all-history timeline must include them rather than silently drop bytes
    # already included in its totals. Bounded queries filter them in SQL.
    last = max(now//3600*3600, hours[-1][0]) if hours else now//3600*3600
    step = 3600*max(1, ((last-first)//3600+23)//24)
    while last//step-first//step+1 > 24:
        step += 3600
    timeline = {bucket:{'bucket':bucket,'download':0,'upload':0}
                for bucket in range(first//step*step, last//step*step+1, step)} if hours else {}
    for hour, upload, download in hours:
        group = hour//step*step
        if group not in timeline:
            continue
        timeline[group]['download'] += download
        timeline[group]['upload'] += upload

    if normalized:
        choice_ips = {}
        for mac, ip in device_labels.values():
            choice_ips[mac] = max(choice_ips.get(mac, ''), ip or '')
    else:
        choice_ips = dict(db.execute('SELECT mac,MAX(ip) FROM hourly GROUP BY mac'))
    choices = []
    for mac in sorted(choice_ips):
        ip = latest_ips.get(mac, choice_ips[mac]) or ''
        choices.append({'mac': mac, 'ip': ip, 'name': names.get(mac, names.get(ip, mac))})
    return {'total':total,'classification_coverage':coverage,
            'app_count':len(apps),'device_count':len(devices),
            'app_page':app_page,'device_page':device_page,'applications':app_rows,
            'devices':device_rows,'device_choices':choices,'timeline':list(timeline.values()),
            'timeline_resolution_seconds':step}
