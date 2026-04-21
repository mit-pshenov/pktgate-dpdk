# Operations

Запуск, supervisor, hot reload, metrics, shutdown. Этот doc — для
оператора, который ставит pktgate-dpdk как сервис и эксплуатирует его
в проде.

## systemd (production skeleton)

В репозитории лежит `systemd/pktgate-devvm.service` — это **dev-only**
test matrix runner (крутит `scripts/run_all.sh`), **не** production unit.
Для прода напишите свой unit по этому шаблону:

```ini
# /etc/systemd/system/pktgate.service
[Unit]
Description=pktgate-dpdk — inline L2/L3 packet filter
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart=/usr/local/bin/pktgate_dpdk \
    --config /etc/pktgate/config.json \
    --ctl-sock /run/pktgate/cmd.sock \
    -l 0-7 \
    -n 4 \
    -a 0000:01:00.0 \
    -a 0000:01:00.1 \
    --file-prefix=pktgate

# Restart policy — pktgate_dpdk exit'ится только по SIGTERM или
# fatal init (bad config, missing hugepages). Автоматический restart
# на hot path не нужен; оператор должен разобраться с причиной.
Restart=on-failure
RestartSec=5s

# EAL init + vfio-pci + hugepages требуют root ИЛИ capabilities.
# Первый вариант — root (проще):
User=root
Group=root

# Второй вариант — unprivileged + capabilities (для compliance):
# User=pktgate
# Group=pktgate
# AmbientCapabilities=CAP_IPC_LOCK CAP_NET_ADMIN CAP_SYS_RAWIO
# CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_SYS_RAWIO

# UDS cmd_socket живёт в /run/pktgate/ — RuntimeDirectory создаёт
# директорию с mode 0750, unlink'ается на stop.
RuntimeDirectory=pktgate
RuntimeDirectoryMode=0750

# Graceful shutdown. pktgate_dpdk ловит SIGTERM + SIGINT → flag
# g_running → drain workers → EAL cleanup. 30s с запасом — в проде
# обычно <5s, но vhost teardown может залипнуть на fdset race (см.
# §Graceful shutdown ниже).
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=30s

# stdout → journald. pktgate пишет JSON events построчно, так что
# `journalctl -u pktgate -o cat -f | jq .` даёт читаемый stream.
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pktgate

[Install]
WantedBy=multi-user.target
```

Активация:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pktgate
journalctl -u pktgate -f -o cat | jq .
```

### Что важно в unit'е

- **EAL argv**: всё что после `--config`/`--ctl-sock` уходит в EAL
  (`-l`, `-n`, `-a`, `--vdev`, `--file-prefix`). Полный список —
  https://doc.dpdk.org/guides-25.11/linux_gsg/linux_eal_parameters.html
- **PCI whitelist (`-a`)**: в проде явно указывать порты pktgate'а
  вместо пробы всех PCI устройств — быстрее boot, меньше шанс
  подцепить чужую NIC.
- **`--file-prefix`**: обязателен если на хосте крутится несколько
  DPDK процессов, иначе конфликт на `/var/run/dpdk/<prefix>/`.
- **Не скипайте `After=network-online.target`** — vhost vdev'у иногда
  нужен готовый networking namespace, а PCI NIC'ам — все DHCP/link
  settlements.

### PKTGATE_DPDK_DRIVER_DIR

Если DPDK установлен из двух источников (source build + дистрибутивный
пакет одновременно) — в EAL upraвляется через env var:

```ini
Environment=PKTGATE_DPDK_DRIVER_DIR=/opt/dpdk-25.11/build/drivers
```

Подробнее — `docs/install.md` §Dual-install caveat.

## CLI args

pktgate_dpdk забирает свои флаги из argv и отдаёт остаток EAL'у. Нет
разделителя `--` — parser просто скипает известные свои ключи.

| Флаг | Обяз. | Дефолт | Описание |
|---|---|---|---|
| `--config <path>` | required | — | Путь до `config.json` |
| `--workers <N>` | optional | auto (lcores − 1) | Количество worker lcore'ов |
| `--mbuf-size <bytes>` | optional | 2048 | Размер mbuf'а в pool'е |
| `--ctl-sock <path>` | optional | не стартует cmd_socket | Путь UDS socket'а для hot reload |
| `--exit-after-init` | optional | off | Boot + init + exit (smoke test) |

`--exit-after-init` полезен для CI smoke и валидации конфига: бинарь
проходит весь init chain (parse → validate → compile → EAL → ports →
ruleset publish → Prometheus bind), логирует `{"ready":true}` и
exit'ится. Не требует `ip link`/живого траффика.

## Hot reload

Pktgate поддерживает reload ruleset'а **без перезапуска процесса** —
конфигу меняются только правила / actions / objects, не EAL topology.
Генерация инкрементится; старый ruleset живёт до QSBR synchronize;
workers бесшовно переключаются на новый.

**Что можно** менять по reload:
- Rules (add/remove/modify в любом слое)
- Actions (verb и параметры)
- `objects.subnets`
- `default_behavior`
- `fragment_policy`

**Что НЕ reload'ится** (требует restart процесса):
- `version`
- `interface_roles` (port topology)
- `sizing` (ёмкости hash'ей/arena'ов закладываются на boot time)
- `cmd_socket.allow_gids`

Попытка reload'нуть «не-reloadable» поле → `kReloadTopologyChange` error,
ruleset не applied, процесс продолжает работать на старом.

### Три канала reload

**1. inotify watcher** (D38, всегда включён):

Pktgate смотрит `IN_CLOSE_WRITE | IN_MOVED_TO` на basename
config-файла в родительской директории. Любой редактор, который
write + close, триггернёт reload:

```bash
sudo vim /etc/pktgate/config.json   # :wq → inotify → reload
# или атомарная замена (правильный способ для скриптов):
sudo install -m 0644 /tmp/new-config.json /etc/pktgate/config.json
```

Events на stdout:

```json
{"event":"inotify_reload_ok","generation":42}
{"event":"inotify_reload_failed","kind":"validate_error","error":"..."}
```

**Gotcha**: много редакторов делают rename через temp file
(`.swp` + atomic rename) — тогда IN_CLOSE_WRITE не срабатывает на
оригинале, но IN_MOVED_TO ловится. Pktgate обрабатывает оба.

**2. UDS cmd_socket** (опциональный, `--ctl-sock <path>`):

Текстовый протокол `reload <json-payload>\n`. Payload — полный JSON
config.

```bash
# Push текущего файла:
echo "reload $(cat /etc/pktgate/config.json | tr -d '\n')" | \
    sudo socat - UNIX-CONNECT:/run/pktgate/cmd.sock

# Reply: "ok <generation>\n" или "err <kind>:<msg>\n"
```

**Важное предупреждение по security.** В shipped build'е (Phase 1
closed, M11 scope-trimmed) cmd_socket **не проверяет SO_PEERCRED** —
`allow_gids` парсится и валидируется, но **не enforcing'ится** в
runtime. Authentication держится на filesystem permissions UDS-путя:
`RuntimeDirectoryMode=0750` + owner/group root даёт root-only доступ.
Post-phase1 debt item — дописать peercred enforcement (см.
`docs/limitations.md`).

**3. DPDK telemetry** (встроен, всегда включён):

DPDK exposes Unix socket `/var/run/dpdk/<file-prefix>/dpdk_telemetry.v2`;
pktgate регистрирует команду `/pktgate/reload` с JSON payload.

```bash
# DPDK ships dpdk-telemetry.py — хелпер для telemetry socket'а.
# Payload — JSON config одной строкой:
echo '/pktgate/reload,{"version":1,...}' | \
    /usr/local/bin/dpdk-telemetry.py --file-prefix pktgate
```

Reply — DPDK telemetry dict `{ok, kind, generation, error?}`.

### Reload flow

Все три канала funnel'ятся через `reload::deploy()` под
`reload_mutex` (D35). Последовательность:

1. Parse → validate → compile (все три могут fail, ruleset не меняется).
2. Publish generation: новый `g_active` атомарно, старый переходит в `pending_free`.
3. QSBR synchronize (timeout 500ms по дефолту) → workers отпустили старые refs.
4. Старый ruleset освобождается.

Bad-config reload атомарно fail'ится до publish — live генерация не
теряется. Timeout на synchronize (worker stuck / lcore died) →
`reload_timeout_total` инкрементится, но новый ruleset всё равно
deployed; старый остаётся в `pending_free` и освободится позже
(когда QSBR станет consistent).

### Reload counters

Observable через Prometheus `pktgate_reload_total{result="..."}`:

| Label | Счётчик | Что значит |
|---|---|---|
| `success` | `reload_success_total` | Deploy прошёл полный chain |
| `parse_error` | `reload_parse_error_total` | JSON syntax / unknown field / type mismatch |
| `validate_error` | `reload_validate_error_total` | Dangling ref / duplicate id / bad transition |
| `compile_error` | `reload_compile_error_total` | Compilation в hash/FIB/compound упала |
| `build_eal_error` | `reload_build_eal_error_total` | EAL-side publish failed |
| `timeout` | `reload_timeout_total` | QSBR synchronize не уложился в deadline |
| `internal_error` | `reload_internal_error_total` | Catch-all |

Подробнее про счётчики — `docs/observability.md`.

## Metrics endpoint (Prometheus)

Pktgate exposes OpenMetrics-compatible `/metrics` на
`127.0.0.1:<prom_port>` (default 9090; настраивается через
`sizing.prom_port`).

```bash
curl -s http://127.0.0.1:9090/metrics | grep ^pktgate_
```

**Loopback only.** Bind'ится строго на `127.0.0.1` (IPv4), не на
`0.0.0.0` / `::`. Если нужен remote scrape — ставьте rev-proxy
(nginx / haproxy) с auth'ом и TLS на том же хосте. Выставлять bare
`/metrics` наружу нельзя — endpoint'у доверяем internal network
boundary, а не public.

**HTTP is handwritten.** Мы не тянем cpp-httplib/boost.beast (D42):
endpoint узкий (single path, GET-only, no auth), а dependency surface
для безопасности лишняя. Парсер request-line'а строгий: non-GET → 405,
path ≠ `/metrics` → 404, malformed → 400.

**Scrape frequency.** Default Prometheus `15s` — ОК. Если хочется
чаще — до 5s без проблем, endpoint renders весь snapshot за
<1ms на типичной prod-size'е.

Pagination нет — весь snapshot одной страницей, ~50-200 KiB на
production ruleset.

### Prometheus config

```yaml
scrape_configs:
  - job_name: pktgate
    static_configs:
      - targets: ['pktgate-host-1:9090']
    metrics_path: /metrics
    scrape_interval: 15s
```

Рекомендуемые alerts — в `docs/observability.md` §Alerts.

## Graceful shutdown

SIGTERM или SIGINT:

1. Signal handler устанавливает `g_running=false` (async-signal-safe atomic).
2. Workers видят на next poll-loop iteration → break из RX burst loop.
3. Main thread join'ит workers → `workers_exit` event.
4. inotify watcher stop → `cmd_socket_stop` → telemetry unregister.
5. `rte_eth_dev_stop` на каждом порту → `ports_stopped`.
6. Ruleset free → `ruleset_freed`.
7. `rte_eal_cleanup` → `eal_cleanup` → exit(0).

Typical total time: <500ms на TAP, <2s на vhost-user с peer'ом.

**Vhost caveat.** DPDK 25.11 net_vhost имеет race в teardown'е —
`fdset_event_dispatch` pthread не join'ится корректно из
`rte_eal_cleanup()`, и процесс может упасть в SEGV. Pktgate
обходит это conditional bypass'ом — когда в pipeline есть хоть один
vhost role, **`rte_eal_cleanup()` пропускается**. Event на stdout:

```json
{"event":"eal_cleanup_skipped","reason":"vhost_role_present"}
```

Процесс всё равно exit'ится с кодом 0, resources GC'ятся OS'ом. Это не
утечка памяти — kernel освобождает hugepages/mempool/sockets корректно,
просто DPDK internal TLS не cleanup'ится. Not a concern для
systemd-supervised long-running daemon. Подробнее — `docs/limitations.md`.

### Kill vs TERM

- `systemctl stop pktgate` → SIGTERM → graceful (~500ms-2s).
- `systemctl kill -s KILL pktgate` → SIGKILL → **mbuf leak** в shmfs.
  Next start подхватит stale `/var/run/dpdk/<prefix>/` и откажется
  init'ить. Чистить: `sudo rm -rf /var/run/dpdk/<prefix>/`.
- `TimeoutStopSec=30s` в unit'е — после тридцати секунд systemd сам
  сделает SIGKILL. Видели случаи где vhost teardown залипал дольше,
  если peer не отвечает; если в логах `eal_cleanup_skipped` систематически,
  stoptimeout можно опустить до 10s.

## Log channel (stdout)

Pktgate пишет JSON events построчно (NDJSON) на stdout. Каждая строка —
валидный JSON object; structured-logging pipeline'ы парсят без
дополнительных prefix'ов.

Ключевые события по порядку boot'а:

```
{"event":"eal_init_ok"}
{"event":"dynfield_registered","offset":92}
{"event":"ports_started","ports_started":2}
{"event":"ruleset_published","generation":1,"l2_rules":0, ...}
{"event":"telemetry_reload_registered"}
{"event":"port_resolved","role":"upstream_port","port_id":0}
{"event":"worker_ports","port_id":0,"tx_port_id":1}
{"event":"prom_endpoint_ready","port":9090}
{"event":"inotify_watch_ready","dir":"/etc/pktgate","basename":"config.json"}
{"ready":true}
```

После `{"ready":true}` процесс полностью operational.

Runtime events:

- `inotify_reload_ok` / `inotify_reload_failed`
- `cmd_socket_reload_ok` / `cmd_socket_reload_failed` (в future build'ах)
- `worker_stall_detected` (if worker не tick'ает N циклов)
- `mirror_slow_consumer` (back-pressure триггер)

Shutdown events:

```
{"event":"workers_exit"}
{"event":"stats_on_exit","rules":[...], "counters":{...}}
{"event":"ports_stopped"}
{"event":"ruleset_freed"}
{"event":"eal_cleanup"}
```

`stats_on_exit` содержит final counter snapshot — удобно для
post-mortem без scrape'а `/metrics`.

## Capacity & sizing tuning

`sizing` в config.json контролирует ёмкости pool'ов (см.
`docs/configuration.md` §sizing). Если видите `kSizingMemoryBudget` на
deploy — снижайте `rules_per_layer_max` / `l4_entries_max`, либо
добавьте hugepages. Pre-flight budget check (D37) делается до publish'а,
так что процесс не рухнёт in-flight.

### Hugepage recomputation

На production: 2 GB на pktgate + 1 GB запаса на rte_fib6 DIR24_8 arena.
Baseline:

```bash
# 4 GB hugepages (2 MB pages):
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# или 1 GB pages (рекомендуется для prod):
# /etc/default/grub: GRUB_CMDLINE_LINUX="... default_hugepagesz=1G hugepagesz=1G hugepages=4"
```

Мониторить: `pktgate_mempool_inuse_count` (должен стремиться к stable
plateau), `pktgate_reload_validate_budget_hugepage_total` (бамп =
pre-flight reject'нул reload по памяти).

## Upgrade workflow

Rolling update одного хоста:

1. `systemctl stop pktgate` (SIGTERM, ~500ms).
2. `install -m 0755 build/dev-release/pktgate_dpdk /usr/local/bin/`.
3. `systemctl start pktgate`; проверить `{"ready":true}` в journald.

Ruleset config не меняется при upgrade бинаря. Если конфиг тоже
обновляется — делать через hot reload ПОСЛЕ restart'а (не до), чтобы
новый бинарь подхватил свежий config без midway-inconsistency'и.

Downtime per host: ~5-15s с учётом EAL re-init. Для HA — нужен второй
хост в bypass / load-balancer pair (M12 watchdog / HA deferred
post-MVP, см. `docs/limitations.md`).
