# Limitations

Что pktgate-dpdk **не** делает, где он валидирован, и что отложено в
post-MVP scope. Цель doc'а — помочь решить, подходит ли он для вашего
use case'а, без неприятных сюрпризов на проде.

## Non-goals (по дизайну, никогда не планируется)

Из `input.md` §4:

- **DPI, L7 parsing, protocol dissection.** Pktgate — pre-filter перед
  DPI, не сам DPI. HTTP/TLS/DNS payload inspection не делаем.
- **TLS fingerprinting (JA3/JA4).** Не матчим по ClientHello/cert metadata.
- **Per-flow state / connection tracking.** No conntrack, no session
  reassembly. Rate-limit — per-lcore token bucket (D1), не per-flow.
- **Encryption / decryption.** Не терминируем TLS/IPSec.
- **Packet modification за пределами DSCP/PCP rewrite.** TAG action —
  единственная форма mutation'а. NAT, proxy, header rewrite — нет.
- **NAT / proxying / L7 routing.** Pktgate — transparent L2/L3 filter.
- **IPS/IDS сигнатурный матчинг.** Нет Suricata/Snort-совместимых правил,
  нет regex на payload'е.

Если что-то из этого списка критично — pktgate-dpdk не ваш tool. Ищите
nDPI / Suricata / CloudShark / commercial offerings.

## Validated deploy profiles

Phase 2 closed с двумя полностью протестированными профилями:

| Profile | Vdev / driver | Статус |
|---|---|---|
| **TAP** (`net_tap0,iface=dtap0`) | DPDK `net_tap` PMD | ✅ CI baseline + dev smoke. TX не имеет true back-pressure (write на `/dev/net/tun` буферизуется в kernel) — используется только для функциональных тестов. |
| **vhost-user** (`net_vhost0,iface=/run/.../sock`) | DPDK `net_vhost` PMD | ✅ Production zero-copy shared-memory profile. Пара с QEMU guest'ом или testpmd peer'ом. |

## Architectural targets (not benched)

Следующие NIC'и поддержаны **архитектурно** — rule tiering, `hw_offload_hint`
hook (D4), queue/RSS config готовы — но deploy на них **не benched** в
dev-окружении (PCI NIC проекту недоступна):

- Intel E810 (`ice` driver) — 100 Gbps class
- Intel XL710 (`i40e` driver) — 40 Gbps class
- Mellanox ConnectX-5 / ConnectX-6 (`mlx5` driver) — 100/200 Gbps class

Что это значит на практике: бинарь **должен** работать на этих NIC'ах
без модификаций кода, но **не** должен считаться production-ready без
независимой валидации заказчиком на target hardware'е. Bench'ить:

- Throughput по всем классам пакетов (64B / 512B / 1518B / 9000B).
- Latency overhead на line rate (SLO N2 ≤500 µs p99).
- RX/TX drop under sustained load.
- rte_flow capability discovery (для post-MVP hw offload v2).

## Post-MVP deferred (будет в v2 / Phase 3 если будет)

### M12 — watchdog / HA / bypass

**Отложено.** Design есть (секция §12 в design.md), реализация — нет.

Что не работает:
- Автоматический restart hang'нутого worker lcore'а.
- Kernel-route bypass если pktgate поломался (`pktgate_bypass_active`
  имя зарезервировано в counter manifest, но не wired в /metrics endpoint).
- Active-standby failover между двумя pktgate инстансами. В design.md
  (D5 anti-patterns раздел) закреплены constraints для будущей HA; в
  Phase 1 scope это не отгружалось, CLI-flag'а `--standby` в argv parser
  нет.

**Workaround до v2:** systemd `Restart=on-failure` + external
health-checker (Prometheus alert → PagerDuty). Downtime при полном
рестарте ~5-15s.

### SO_PEERCRED enforcement на cmd_socket

**Частично отложено.** `allow_gids` **парсится и валидируется**, но в
shipped build'е **runtime enforcement не wired** (M11 scope-trim,
post-phase1 debt).

Что это значит: любой процесс с filesystem access к UDS socket'у может
посылать reload commands. Authentication держится на **filesystem
permissions** (`RuntimeDirectoryMode=0750` + root:root owner/group в
systemd unit'е — см. `docs/operations.md`).

Для большинства setup'ов этого достаточно: pktgate работает как root,
UDS path под `/run/pktgate/` с mode 0750, только root сможет открыть.
Для scenarios с non-root operator'ами нужен доп. wrapping (sudoers rule
на конкретную reload-команду, например).

### rte_flow hw offload v2

**Archived as growth hook (P7, resolved).** D4 clause 6 описывает
ожидаемый dual-path с topological promotion; выбор между naive и
topological promotion — empirical decision для реального HW'а и
трафика, не архитектурная. Bench on E810/ConnectX-6 решит — архитектурные
hooks готовы.

### Mirror refcnt zero-copy (D26)

**Отложено.** В M16 shipped **deep-copy mirror** (`rte_pktmbuf_copy`).
Rationale: D26 compile-time gate `MUTATING_VERBS` — если pipeline может
мутировать mbuf (TAG/REDIRECT в downstream), refcnt zero-copy ломает
оригинал (shared payload) или клон (если оригинал изменён после staging'а).

Cost trade-off: deep-copy = 1 extra `rte_pktmbuf_copy` call per mirror'нутый
пакет, ~200-400ns на pktgate'ом profile'е. Для трафика где mirror — узкая
полоса (compliance / IDS sample), это ОК. Для mirror-heavy workloads
(full span port) — v2 refcnt path.

### L7 rate-limit (per-flow buckets)

Per-lcore token bucket (D1) даёт **~10-20% aggregate rate error** под
skewed RSS распределением. Для equal-share traffic'а точность <5%.

Если нужна **per-flow** rate limiting (RFC 3168 AQM / Cake-style fq_codel) —
это v2 scope, требует flow-state tracking которого нет в non-goals.

### IPv6 extension header scope

**D20 — first-protocol-only.** В L4 matching читается только первый
`next_header` после IPv6 base header:

- ICMPv6, TCP, UDP — матчатся нормально.
- Fragment header (44) — non-first fragment пропускается per
  `fragment_policy`.
- HbH (0), Destination (60), Routing (43), ESP (50), AH (51) — L4
  matcher пропускает пакет как "extension present" → бамп
  `lcore_l4_skipped_ipv6_extheader_total`, далее default path.

Если ожидается трафик с HbH/Destination в significant volume — текущий
build все эти пакеты пропустит через L4 rules без match'а. v2 может
расширить scope до chain walk.

### Schema version 1 — no migrations

Pre-freeze, backcompat shim'ов нет. Любая несовместимая смена формата
→ `version = 2`, config должен быть переписан. Sitemap grep на
`kSchemaVersion` покажет зависимости в коде.

## Runtime & environment limitations

### Single NUMA node default

pktgate НЕ делает automatic NUMA-aware placement mempool'ов и worker'ов
при multi-socket host'е. CLI argument `-l 0-7` на socket'е 0 + NIC на
socket'е 1 = cross-socket DMA + QPI latency penalty.

**Workaround.** Вручную выставить lcore mask на той же NUMA что NIC:

```bash
# Найти NUMA NIC'а:
cat /sys/bus/pci/devices/0000:01:00.0/numa_node  # например "1"

# Выделить lcore'ы только на этой NUMA:
numactl -H  # видим диапазоны
# -l 8-15 если NUMA 1 = cpu 8-15
```

Multi-socket рекомендация в `docs/install.md` §Системные требования,
но automation'а нет.

### Hugepage requirement hard

Никакого fallback на mmap(MAP_HUGETLB) нет. Отсутствие hugepages →
rte_eal_init fail + exit. Это DPDK constraint, не pktgate.

### Root / capabilities required

`CAP_IPC_LOCK + CAP_NET_ADMIN + CAP_SYS_RAWIO` минимум. В большинстве
prod deploy'ев — просто root, systemd `User=root`. Unprivileged +
ambient capabilities технически работает, но в тестах не
валидировалось — используйте на свой страх и риск.

### TSC-based latency measurement

`lcore_cycles_per_burst` histogram — в TSC cycles, не в секундах. Для
SI conversion нужна `tsc_hz` (DPDK выставляет при init; можно забрать
через dpdk-telemetry.py `/eal/tsc_hz`). Real-time wall-clock latency
восстанавливается как `cycles / tsc_hz`.

TSC assumed constant и invariant — стандарт для производительных Intel
CPUs последних 10 лет. На bare-metal Xeon (таргет production-deploy'ев)
показания стабильны. На виртуализированных VM'ках (особенно без
hw-assisted TSC) показания могут плавать; dev VM проекта — именно такой
случай.

### mbuf pool sizing

Default 8191 mbufs × 2048 bytes = ~16 MiB. При burst'ах под
линейную скорость 40 Gbps mbuf'ы turnover'ятся за ~12ms, что обычно ОК,
но **сильный skewed ingress** (весь трафик на одной queue) может выжрать
pool до bottom.

Override через env:

```bash
PKTGATE_TEST_MBUF_POOL_SIZE=32767 systemctl start pktgate
```

**Замечание.** Имя переменной исторически несёт префикс `TEST_` (введена
под test harness в M16 C4, `src/main.cpp:419`), но в коде нет проверки на
test/prod mode — переменная читается одинаково в любом контексте. На
production ставить можно; переименовать без breaking CI-тестов нельзя,
поэтому имя зафиксировано. Если в unit'е — через `Environment=` в `[Service]`.

## Known bugs / quirks

### `rte_eal_cleanup()` skip при shutdown с vhost role

**Известная DPDK 25.11 issue.** `net_vhost` не join'ит fdset_event_dispatch
pthread на `rte_eal_cleanup()`, что приводит к SEGV in cleanup path.
Pktgate обходит conditional bypass'ом — cleanup **пропускается** когда в
pipeline'е есть vhost role. Kernel освобождает resources за процессом
корректно, это не memory leak в OS terms. Отдельного event'а про skip
не эмиттится: `{"event":"eal_cleanup"}` пишется в обоих режимах (см.
`docs/operations.md` §Vhost caveat).

### IFNAMSIZ silent truncation на net_tap

Имена TAP интерфейсов > 15 байт silent truncated Linux kernel'ом,
net_tap vdev после этого теряется из DPDK port list'а → "insufficient
ports" на boot'е. Budget iface name ≤ 13 chars с запасом на суффикс
(DPDK добавляет префикс типа `_qinq`/`_ingress` при multi-queue setup'е).

## Что делать если hit'нули limitation

1. **Проверить, что это именно limitation, а не bug.** Читать
   `docs/troubleshooting.md` — там 90% симптомов на известные корнеры.
2. **Проверить `implementation-plan-errata.md`** — closures и workaround'ы
   по закрытым debt item'ам живут там, с привязкой к commit'ам.
3. **Для prod-grade deployment'ов** — provide feedback через PR /
   issue'сы с конкретным use case'ом. Архитектурный growth есть (D4
   rte_flow, D7 mirror zero-copy, M12 HA) — в roadmap'е, вопрос
   приоритизации.
4. **Для compliance / audit** — `input.md` содержит формализованные
   SLO и feature matrix, `review-notes.md` — motivation trail каждого
   D-decision'а. Всё open, reproducible, git-traceable.
