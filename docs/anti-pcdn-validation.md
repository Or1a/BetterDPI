# Anti-PCDN experimental validation

These measurements test implementation overhead and bounded state, not PCDN
detection accuracy or router throughput. They used synthetic Netify messages on
the development host on 2026-11-01. They do not replace testing with labelled
traffic or an OpenWrt router.

## Host and method

- Host: x86_64 KVM guest, AMD EPYC 9V74, five visible virtual CPUs;
  Linux 6.18.57, Python 3.12.14.
- Each throughput result uses one warm-up followed by seven timed repetitions;
  tables report medians. Garbage collection remained enabled. Timing used
  `time.perf_counter()`; these are elapsed times, not measured CPU utilisation.
- The actual `Collector.read_message()` parsed and validated serialized JSON.
  Its accounting handler was replaced with the same no-op in every case to
  isolate the new feature path. SQLite writes and Netify socket I/O are excluded.
- The disabled baseline removes only the new feature-dispatch statements from
  the current method in memory. The comparison has an inactive `FeatureBridge`.
  Their order alternates between repetitions. A separate parsed-message case
  isolates the conditional dispatch without JSON decoding.
- Enabled cases execute the real `FeatureBridge.submit()`, `Worker.submit()`
  projection, bounded queue put/get, `Worker.consume()`, and `Engine.observe()`.
  A fake firewall rejects any attempted install; mode is `observe`.
  Batches of at most 128 events are queued and then consumed synchronously.
  This measures the implementation path but excludes background-thread
  scheduling and contention with the main collector.
- Each flow receives metadata and 30 updates, one every ten simulated seconds,
  spanning five minutes. There are 50 remote peers per device, split between
  TCP/TLS and UDP/QUIC, with mixed upload-heavy and download-heavy increments.
  The 250-flow case has five devices and ten scoring groups; the 1,000-flow
  case has 20 devices and 40 groups. Evaluation runs after each update round.
- Configuration polling, status-file publication, firewall commands, neighbour
  lookup and conntrack lookup are excluded. Nothing installs a kernel rule.

## Disabled feature

Each repetition handles 62,000 metadata/statistics messages.

| Path | Median time per message | Median messages/second |
| --- | ---: | ---: |
| Parse/validate, without feature dispatch | 3.782 µs | 264,418 |
| Parse/validate, feature disabled | 3.699 µs | 270,310 |
| Already parsed, without feature dispatch | 0.0649 µs | 15,406,536 |
| Already parsed, feature disabled | 0.0973 µs | 10,274,278 |

The apparent improvement in the JSON case is timing noise, not a speedup.
Paired repetitions give a median additional 46.8 ns/message, with deltas ranging
from −143.5 to +272.1 ns/message. The isolated parsed dispatch gives a paired
median additional 30.3 ns/message. The useful conclusion is that the disabled
event hook is small relative to JSON decoding on this host; this is not an
OpenWrt performance prediction.

## Enabled observation

These times include parsing, projection, queue operations, engine ingestion and
30 evaluations, but exclude the operations listed above.

| Workload | Events | Median total | Median events/second | Median evaluation |
| --- | ---: | ---: | ---: | ---: |
| 250 flows, 30 updates each | 7,750 | 0.316 s | 24,526 | 6.47 ms |
| 1,000 flows, 30 updates each | 31,000 | 1.113 s | 27,858 | 21.89 ms |

Evaluations occur once per ten simulated seconds, not once per event. The
largest individual evaluations across the seven runs were 15.00 ms and
65.04 ms respectively. The higher event rate in the larger workload does not
mean better scaling: that workload reaches the sample cap and rejects later
samples, avoiding some downstream work.

All 7,500 statistics updates in the 250-flow workload were accepted. In the
1,000-flow workload, storage stopped at the configured **16,384 samples**;
13,616 later updates incremented `sample_drops`. No queue overflow or malformed
message occurred. At the end of the saturated case no fresh candidate rows
remained. This is an explicit coverage loss: incomplete evidence must not be
treated as zero traffic or as permission to block. The cap limits memory but
does not guarantee full five-minute coverage for 1,000 simultaneously active
flows reporting every ten seconds.

## Python allocation measurement

A separate `tracemalloc` run used the 1,000-flow workload. Input fixtures were
allocated before tracing. After the queue drained and garbage collection ran,
retained traced allocations above the initial baseline were **4,638,198 bytes
(4.42 MiB)**; the observed peak was **6,504,614 bytes (6.20 MiB)**. This includes
the instantiated bridge/worker/engine and transient evaluation allocations.

These are one instrumented run's Python allocations, **not process RSS**, a
whole-plugin memory cap, or a maximum for all possible event shapes. The queue
batch size was 128, below its 512-event limit. Allocation tracing substantially
slows Python execution, so its timings are not used in the throughput table.

## Reproduction artifacts and measured source

The reproducible benchmark is `netify-stats/bench_anti_pcdn.py`. It is included
in the source archive and excluded from the installed router runtime. From the
repository root:

```sh
python3 netify-stats/bench_anti_pcdn.py baseline
python3 netify-stats/bench_anti_pcdn.py 250
python3 netify-stats/bench_anti_pcdn.py 1000
python3 netify-stats/bench_anti_pcdn.py memory
```

Outputs are `/tmp/betterdpi-pcdn-benchmark-{baseline,250,1000,memory}.json`.
They record all repetitions, counters, limits, host details and source SHA-256
hashes before and after each run. Use `--output-dir PATH` to retain results
elsewhere; the default is the system temporary directory. Raw measurements are
not committed. Source files resolve relative to the benchmark script, so a
different checkout path is supported.

The final enabled/allocation measurements used these exact source snapshots;
hashes stayed unchanged within each measured run:

| Source | SHA-256 |
| --- | --- |
| `netify-stats/netify_collector.py` | `3d707e9e57fd500147fc956319a37964999296757148a80bc650dcb7d0370787` |
| `netify-stats/netify_features.py` | `ab5935653770bc99c63b7fc181c6895f87ddd41bb1b50d8efc683c50f4ad186c` |
| `netify-stats/features/anti_pcdn/engine.py` | `61c48f2889cef901c2c837a774777eec4df067e03c39f4def076f46e6f742e88` |
| `netify-stats/features/anti_pcdn/runtime.py` | `fe5e74d491cb1a3b85ea0fa2d9fc3a88b1d9af308401e6ff4cb3e536b54b9321` |

The disabled benchmark used the same collector and bridge snapshots; its
engine import was an earlier snapshot but the engine was never instantiated
or called in that case. These numbers describe the measured snapshots only.

## Independent page translation loading

The pinned official LuCI source used for the catalog compiler was also checked
for catalog loading, revision `0e6537981036ea221a73e497920192179e9f74c3`:

- `modules/luci-base/ucode/dispatcher.uc` loads catalogs for the selected
  language from `/usr/lib/lua/luci/i18n`.
- `modules/luci-base/src/lib/lmo.c`, `lmo_load_catalog()`, scans every
  `*.LANG.lmo` file in that directory. Catalog loading is not tied to a view or
  menu filename.
- `modules/luci-base/ucode/controller/admin/index.uc`,
  `action_translations()`, exposes all loaded translations in `window.TR`.

Therefore the independent Anti-PCDN page can use the installed
`netify-stats.zh-cn.lmo` and `netify-stats.zh-tw.lmo` files without an additional
translation-domain dependency. A host probe linked against the official
`lmo.c` resolved all **82 Anti-PCDN keys** from each compiled catalog. That probe
also caught and led to fixing seven trailing-space gettext keys that the Node
PO-based fixture had accepted. A regression assertion now keeps whitespace
padding outside gettext keys. This verifies the compiled catalogs and loading
mechanism; it is not a live-router browser test.

## Regression and kernel checks

The full Python regression run passed 241 tests; two subsequently added strict
protocol-type cases also passed in the 65-test engine/firewall/runtime run.
All ten Node suites passed, including the new view and both translation catalogs.
The late-REDIRECT reproduction still records exactly 100 upload bytes, 200
download bytes and one flow. Source preparation validates 35 runtime files and
19 Python modules; the existing public-release readiness gate remains false.

Run the ordinary checks from the repository root:

```sh
python3 -m unittest discover -s netify-stats -p 'test_*.py'
python3 netify-stats/reproduce_late_original.py
python3 netify-stats/packaging/check_preparation.py
node netify-stats/test_anti_pcdn_ui.cjs
node netify-stats/test_i18n_ui.cjs
```

Actual software-kernel tests used Linux 6.18.57 and nft 1.1.3 in fresh user and
network namespaces. They passed IPv4/IPv6 TCP/UDP outbound connections and
IPv4/IPv6 UDP inbound connections without DNAT, exercising exact conntrack and
neighbour queries, two-observation identity checks, both-direction blocking,
an unaffected second source port, no renewal from repeated installs, manual
release, independent 30-second kernel expiry and owned-table cleanup. Mapping
the real CT ID to an intentionally wrong original source port allowed both
directions; restoring the exact tuple blocked them.

The fixture supplies a minimal synthetic fw4 chain and an empty module
inventory because the test namespaces do not expose `/proc/modules`. It does
not validate actual OpenWrt fw4 integration, SNAT deployment, hardware/vendor
acceleration, DNAT, inbound TCP, shared proxy paths or PCDN detection accuracy.

The optional, non-CI fixture is preserved in the repository:

```sh
python3 netify-stats/check_anti_pcdn_kernel.py
# Supply --nft /absolute/path/to/nft if it is not on PATH.
```

It requires Linux user/network namespaces, `nft`, `ip` and `nsenter`. Its public
launcher always creates isolated namespaces; before network writes the worker
verifies a live-parent pipe handshake, changed user/network namespaces and a
fresh network. There is no host-firewall fallback if isolation fails. Normal
unit tests and the benchmark never install kernel rules.

## V0.4.0 trial package publication

On 2026-11-01, [release workflow 41261234399](https://github.com/Or1a/BetterDPI/actions/runs/41261234399)
completed both official SDK builds and published V0.4.0 as a prerelease from
commit `f534d127fa86045c454433ce2a591965b34c0d7f`. The release preparation run
passed all 243 Python tests and ten Node suites. The stable `releases/latest`
page was separately confirmed to remain on V0.3.2.

All six published assets were downloaded. SHA256SUMS, fixed-name aliases and
the version/size/hash entries in update.json agree. Both packages contain the
exact 35 runtime files from the tagged manifest, with matching bytes, modes and
root ownership. The IPK has no additional payload files; the APK adds only the
official SDK package file list. APK scripts were checked against the complete
OpenWrt v25.12.5 wrapper template and the tagged custom hooks, including the
post-upgrade hook. Configuration defaults remain disabled, observation mode,
threshold 80 and lease duration 120 seconds. Packages were inspected without
installing them or running lifecycle scripts on the development host.

| Package | Bytes | SHA-256 |
| --- | ---: | --- |
| `BetterDPI-0.4.0-openwrt-24.10.8-all.ipk` | 275348 | `ecc99e6c4267578f9fab69c3c383be66dcdb71d8b9cb963368cf1eddef7d8ef5` |
| `BetterDPI-0.4.0-openwrt-25.12.5-all.apk` | 272803 | `f2771a2461ce6070dddc0467ecaefe15f497e8cf45e2d30d036cfd66f395c00c` |

This verifies downloadable package construction and contents. Actual router
upgrade/restart behavior, workload accuracy and device resource costs remain
for the trial; the source-check release-readiness flag is unchanged.
