"""Aggregate compact SQLite dimensions before classifying application groups."""
from heapq import nsmallest


def _add(target, upload, download, flows):
    target['upload'] += upload
    target['download'] += download
    target['flows'] += flows


def _counts(**labels):
    return dict(upload=0, download=0, flows=0, **labels)


def aggregate(db, start, device, now, classifier, names, latest_ips,
              app_page, device_page, sort_key, direction, expanded):
    normalized = bool(db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='hourly_data'").fetchone())
    device_labels = dict((key, (mac, ip)) for key, mac, ip in db.execute(
        'SELECT id,mac,ip FROM traffic_devices')) if normalized else {}
    native_labels = dict(db.execute('SELECT id,value FROM traffic_apps')) if normalized else {}
    table = 'hourly_data' if normalized else 'hourly'
    native_column = 'app_id' if normalized else 'application'
    args = [start]
    where = 'bucket >= ?'
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

    # The primary key begins with bucket/device, so this grouping streams in
    # index order without a temporary sort. It supplies both device totals and
    # the timeline in one scan; historical IPs still fold into the same MAC.
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

    requested = set(expanded)
    detail_hosts, detail_members = {}, {}
    app_sql = 'SELECT %s,host,%s FROM %s WHERE %s GROUP BY %s,host' % (
        native_column, sums, table, where, native_column)
    for native_key, host, upload, download, flows in db.execute(app_sql, args):
        native = native_labels[native_key] if normalized else native_key
        app = classifier.classify(native, host)
        if app not in apps:
            apps[app] = _counts(id=app)
        _add(apps[app], upload, download, flows)
        if app in requested:
            detail_members[(native_key, host)] = app
            if host and host.lower() != 'unknown':
                hosts = detail_hosts.setdefault(app, {})
                if host not in hosts:
                    hosts[host] = _counts(name=host)
                _add(hosts[host], upload, download, flows)

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
    # the selected native/host combinations instead of rerun for every record.
    selected = {row['id']:row for row in app_rows if row['id'] in expanded}
    if selected:
        app_devices = {key:{} for key in selected}
        native_keys = sorted({key[0] for key, app in detail_members.items() if app in selected})
        detail_where = where+' AND '+native_column+' IN (%s)' % ','.join('?' for _ in native_keys)
        detail_columns = device_columns+','+native_column+',host'
        sql = 'SELECT %s,%s FROM %s WHERE %s GROUP BY %s' % (
            detail_columns, sums, table, detail_where, detail_columns)
        for row in db.execute(sql, args+native_keys):
            if normalized:
                key, native_key, host, upload, download, flows = row
                mac, ip = device_labels[key]
            else:
                mac, ip, native_key, host, upload, download, flows = row
            app = detail_members.get((native_key, host))
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
    step = 3600*max(1, ((now-first)//3600+23)//24)
    while now//step-first//step+1 > 24:
        step += 3600
    timeline = {bucket:{'bucket':bucket,'download':0,'upload':0}
                for bucket in range(first//step*step, now//step*step+1, step)} if hours else {}
    for hour, upload, download in hours:
        group = hour//step*step
        if group not in timeline:
            continue
        timeline[group]['download'] += download
        timeline[group]['upload'] += upload

    all_macs = sorted({labels[0] for labels in device_labels.values()}) if normalized else [
        row[0] for row in db.execute('SELECT DISTINCT mac FROM hourly ORDER BY mac')]
    choices = [{'mac':mac,'name':names.get(mac,mac)} for mac in all_macs]
    return {'total':total,'app_count':len(apps),'device_count':len(devices),
            'app_page':app_page,'device_page':device_page,'applications':app_rows,
            'devices':device_rows,'device_choices':choices,'timeline':list(timeline.values()),
            'timeline_resolution_seconds':step}
