# Observability

Prometheus `/metrics` reference. Counter manifest (41 имени, source of
truth — `src/telemetry/counter_names.h` константа `kAllCounterNames`)
сгруппирован по семействам (rule / port / lcore / dispatch / reload /
system / watchdog).

**Manifest vs exposed.** `kAllCounterNames` — это D33-invariant set:
каждый name там имеет row в design.md §10.3 и закреплён D33-гейтом на
consistency. Но **не все 41 имени wired в /metrics endpoint** в Phase 1
build'е — под ~9 именами зарезервированы slot'ы в manifest'е, но
producer site в `main.cpp` BodyFn ещё не добавлен (или вообще не будет
— watchdog/bypass относятся к M12, который deferred). Таблицы ниже
помечают такие row'ы как **exposed: no** — оператор не увидит их в
scrape'е.

Metric type column: **C** = Counter (monotonic), **G** = Gauge
(instantaneous), **H** = Histogram.

## Семейство rule (4)

Бампятся в worker hot path при match rule'а или в default-path при
полном пролёте pipeline'а. Per-lcore бамп `relaxed_bump`, aggregate на
publisher tick (zero atomics, D1-clean).

| Name | Type | Labels | Семантика / триггер внимания |
|---|---|---|---|
| `pktgate_rule_packets_total` | C | `rule_id` | Пакет смэтчился на rule и applied action. Baseline counter — строят flame chart на rule_id. |
| `pktgate_rule_bytes_total` | C | `rule_id` | Суммарный объём в байтах. Attention: резкий perf shift между packets/bytes ratio → сигнатура traffic drift'а. |
| `pktgate_rule_drops_total` | C | `rule_id` | Drop по action этого rule'а (action=drop или rate-limit дропнул через cap). Attention: skyrocket → DDoS или rate-limit'а не хватает. |
| `pktgate_default_action_total` | C | — | Пакет не смэтчил ни одного rule во всех слоях → applied `default_behavior`. Attention: если `default_behavior=drop` и counter растёт быстрее baseline — дыра в rulesets. |

## Семейство port (9)

Per-port stats, включая DPDK-level RX/TX и собственные backpressure
counter'ы pktgate'а. `pktgate_tx_dropped_total` и
`pktgate_port_tx_dropped_total` — **два имени не опечатка**: первое
считается pktgate-wrapper'ом вокруг `rte_eth_tx_burst`, второе — PMD-level
drop, репортуемый самим DPDK в `rte_eth_stats`. В stable state числа
совпадают; расхождение — сигнал что hook не покрыл какой-то TX path.

| Name | Type | Labels | Семантика / триггер внимания |
|---|---|---|---|
| `pktgate_port_rx_packets_total` | C | `port="0"` и т.д. | RX pps с NIC'а. Baseline — должен совпадать с upstream sensor'ами. |
| `pktgate_port_tx_packets_total` | C | `port` | TX pps на NIC. Attention: RX − TX − drops должен сходиться; gap → silent loss. |
| `pktgate_port_rx_bytes_total` | C | `port` | RX объём. |
| `pktgate_port_tx_bytes_total` | C | `port` | TX объём. |
| `pktgate_port_rx_dropped_total` | C | `port` | Dropped at NIC RX ring (mempool exhaustion, overrun). Attention: **любой** ненулевой рост — backpressure на dataplane. Проверять `mempool_in_use`, `lcore_cycles_per_burst`. |
| `pktgate_port_tx_dropped_total` | C | `port` | PMD'ом отказано в TX (ring full при переднем процессе). Attention: sustained → peer consumer медленнее line rate. |
| `pktgate_port_link_up` | G | `port` | `1` если link up, `0` иначе. Alert: `== 0` дольше 10s. |
| `pktgate_tx_dropped_total` | C | `port` | pktgate's own wrapper зарегистрировал unsent пакет после `rte_eth_tx_burst`. D43 — тот же физический drop, что `port_tx_dropped`, но измерен до/после PMD hook'ов для cross-check. |
| `pktgate_tx_burst_short_total` | C | `port` | `rte_eth_tx_burst` вернул меньше запрошенного (back-pressure signal). Attention: burst_short/burst ratio > 10% sustained → peer не поспевает. |

## Семейство lcore (12)

Per-lcore counter'ы, labeled `lcore`. Каждый worker держит свою копию
(`struct WorkerCtx`), publisher thread суммирует на tick.

| Name | Type | Labels | Семантика / триггер внимания |
|---|---|---|---|
| `pktgate_lcore_packets_total` | C | `lcore` | **exposed: no** — в manifest, producer site в Phase 1 не wired. |
| `pktgate_lcore_cycles_per_burst` | H | `lcore` | **exposed: no** — в manifest как histogram, но emit path в Phase 1 не wired. SLO-критический (N2 ≤500 µs p99) — пока backport не сделан, latency бюджет валидируется только по M10/M15 bench'ам, не live-scrape. |
| `pktgate_lcore_idle_iters_total` | C | `lcore` | **exposed: no** — в manifest, producer site в Phase 1 не wired. |
| `pktgate_lcore_l4_skipped_ipv6_extheader_total` | C | `lcore` | IPv6 пакет с extension header → L4 matcher пропустил (D20 first-protocol-only). Attention: неожиданный growth → трафик использует ESP/AH/HbH, нужно расширять ext-header scope. |
| `pktgate_lcore_l4_skipped_ipv6_fragment_nonfirst_total` | C | `lcore` | Non-first IPv6 fragment с `fragment_policy=l3_only` — L4 match пропущен. См. `docs/configuration.md` §fragment_policy. |
| `pktgate_lcore_tag_pcp_noop_untagged_total` | C | `lcore` | Action `tag` с заданным `pcp` применился к пакету без VLAN тега → no-op (некуда писать). Не ошибка, но сигнал что rule таргетит не ту трафик. |
| `pktgate_lcore_dispatch_unreachable_total` | C | `lcore` | Internal switch default — reached unreachable в apply_action (D25). **Always zero в норме**; любой рост → software bug, escalate. |
| `pktgate_lcore_pkt_truncated_total` | C | `lcore` | Пакет короче чем нужен parser'у (L2/L3/L4) → safe reject (D31). Attention: sustained рост → upstream шлёт truncated frames, проверять cables/SFP. |
| `pktgate_lcore_qinq_outer_only_total` | C | `lcore` | QinQ frame (0x88A8) accepted под outer tag (D32); inner VLAN matched via обычный vlan_id-путь. Baseline informational. |
| `pktgate_lcore_pkt_multiseg_drop_total` | C | `lcore` | Multi-segment mbuf reject (D39 headers-in-first-seg invariant). Sustained рост → NIC шлёт scatter mbuf'ы, проверять `scatter` flag в PMD config. |
| `pktgate_lcore_pkt_frag_skipped_total` | C | `lcore` | IPv4/IPv6 non-first fragment с `fragment_policy=l3_only` → passthrough по L3 rule'ам only. |
| `pktgate_lcore_pkt_frag_dropped_total` | C | `lcore` | Non-first fragment с `fragment_policy=drop` → dropped. Attention: рост после переключения на `drop` — baseline traffic включает фрагменты, возможно надо оставаться на `l3_only`. |

## Семейство dispatch / mirror / redirect (4)

| Name | Type | Labels | Семантика / триггер внимания |
|---|---|---|---|
| `pktgate_redirect_dropped_total` | C | `target_port` | Action `target-port` не смог положить в TX ring target'а (ring full). Attention: sustained → target port underprovisioned. |
| `pktgate_mirror_sent_total` | C | `target_port` | Mirror clone staged в mirror_tx ring. Success at stage time. |
| `pktgate_mirror_clone_failed_total` | C | `target_port` | `rte_pktmbuf_copy` вернул null (mempool exhausted). Оригинал всё равно форвардится. Attention: steady рост → mempool size мал, или mirror target очень slow. |
| `pktgate_mirror_dropped_total` | C | `target_port` | Clone staged но не ушёл (short tx_burst в drain loop) **или** dropped at stage time из-за buffer full. Attention: M16 back-pressure mechanism именно здесь видно — peer DPI/IDS медленнее line rate. |

## Семейство reload / control plane (7)

Hot reload observability — все три канала (inotify / cmd_socket / telemetry)
funnel'ятся сюда.

| Name | Type | Labels | Семантика / триггер внимания |
|---|---|---|---|
| `pktgate_reload_total` | C | `result=success \| parse_error \| validate_error \| compile_error \| build_eal_error \| timeout \| internal_error` | Успех / тип ошибки reload'а. Alert: `result="parse_error"` growing → ops pushed bad config. |
| `pktgate_reload_latency_seconds` | G | — | Latency последнего reload'а (от deploy() до publish, включая QSBR synchronize), в секундах. Manifest type — Histogram, но в Phase 1 wired как gauge on last-observed value. Norm <100 ms. Attention: >1 s → QSBR timeout, worker stuck. |
| `pktgate_reload_pending_free_depth` | G | — | Количество отложенных освобождений (timeout path). Norm = 0. Sustained >0 → worker died mid-reload или live-lock. |
| `pktgate_active_generation` | G | — | Generation живого ruleset'а (monotonic increment on successful reload). Exposition — для debugging. |
| `pktgate_active_rules` | G | `layer` | Количество rules в каждом слое текущего generation'а. |
| `pktgate_cmd_socket_rejected_total` | C | `reason` | **exposed: no** — в manifest, producer site в Phase 1 не wired (cmd_socket SO_PEERCRED enforcement тоже deferred, см. `docs/limitations.md`). |
| `pktgate_publisher_generation` | G | — | Последняя generation которую publisher thread **видел**. Invariant: `publisher_generation == active_generation` после QSBR settle. Growing gap → publisher stuck. |

## Системные gauge'и (2)

| Name | Type | Labels | Семантика / триггер внимания |
|---|---|---|---|
| `pktgate_mempool_in_use` | G | — | **exposed: no** — в manifest, producer site в Phase 1 не wired. Для оперативного мониторинга mempool'а использовать DPDK telemetry: `dpdk-telemetry.py /mempool/info,pktgate_mbuf_pool`. |
| `pktgate_mempool_free` | G | — | **exposed: no** — см. выше, тот же fallback через DPDK telemetry. |

## Watchdog / bypass / log (3)

Все три row'а зарезервированы в manifest'е для Phase 2+ и **в /metrics
не emit'ятся** в Phase 1 build'е.

| Name | Type | Labels | Семантика (когда будет wired) |
|---|---|---|---|
| `pktgate_watchdog_restarts_total` | C | — | **exposed: no** — M12 deferred. Count рестартов worker thread'а watchdog'ом. |
| `pktgate_bypass_active` | G | — | **exposed: no** — M12 deferred. `1` если pktgate в bypass mode (kernel-route в обход DPDK). |
| `pktgate_log_dropped_total` | C | — | **exposed: no** — JSON-лог ring-buffer fallback ещё не wired. |

## SLO mapping (N1-N5 из input.md)

| SLO | Target | Key metric |
|---|---|---|
| N1 — throughput | 40 Gbps per site | `rate(port_rx_bytes[1m])` + `rate(port_tx_bytes[1m])` |
| N2 — p99 latency | ≤500 µs overhead | `histogram_quantile(0.99, rate(lcore_cycles_per_burst_bucket[5m]))` × nanos-per-cycle |
| N3 — packet loss | <0.01% | `rate(port_rx_dropped[5m]) / rate(port_rx_packets[5m])` |
| N4 — reload latency | ≤500 ms | `histogram_quantile(0.99, rate(reload_latency_seconds_bucket[10m]))` |
| N5 — availability | 99.9% | `pktgate_port_link_up == 1` + `up{job="pktgate"}` |

## Recommended alerts

Правила ниже используют **только** exposed-метрики Phase 1 — скопировать
в Prometheus rules и они сработают сразу. Alerts, которые зависят от
exposed: no метрик (lcore latency histogram, mempool gauge'и), вынесены
отдельным блоком «Deferred alerts» ниже.

```yaml
# Prometheus rules примеры (Phase 1 — только exposed метрики).

- alert: PktgatePortDown
  expr: pktgate_port_link_up == 0
  for: 10s
  annotations:
    summary: "pktgate port {{ $labels.port }} link down"

- alert: PktgateHighDropRate
  expr: rate(pktgate_port_rx_dropped_total[1m]) > 10
  for: 30s
  annotations:
    summary: "RX drops on port {{ $labels.port }} > 10 pps sustained"

- alert: PktgateTxBackpressure
  expr: rate(pktgate_tx_burst_short_total[1m]) / rate(pktgate_port_tx_packets_total[1m]) > 0.1
  for: 2m
  annotations:
    summary: "TX burst short ratio > 10% on port {{ $labels.port }} (peer too slow)"

- alert: PktgateReloadFailing
  expr: rate(pktgate_reload_total{result!="success"}[5m]) > 0
  for: 2m
  annotations:
    summary: "Reloads failing (kind={{ $labels.result }})"

- alert: PktgateReloadLatencyHigh
  expr: pktgate_reload_latency_seconds > 1
  for: 1m
  annotations:
    summary: "Last reload took >1s (QSBR settle slow or worker stuck)"

- alert: PktgatePublisherLag
  expr: (pktgate_active_generation - pktgate_publisher_generation) > 0
  for: 30s
  annotations:
    summary: "publisher behind active generation by {{ $value }} — publisher stuck"

- alert: PktgateMirrorBackpressure
  expr: rate(pktgate_mirror_dropped_total[5m]) > 0
  for: 5m
  annotations:
    summary: "Mirror peer slow — clones dropped on {{ $labels.target_port }}"

- alert: PktgateRedirectDropping
  expr: rate(pktgate_redirect_dropped_total[5m]) > 0
  for: 2m
  annotations:
    summary: "redirect TX ring full on {{ $labels.target_port }} — target underprovisioned"

- alert: PktgateUnreachableBranch
  expr: increase(pktgate_lcore_dispatch_unreachable_total[5m]) > 0
  for: 0s
  annotations:
    summary: "software bug — dispatch unreachable branch hit on lcore {{ $labels.lcore }}"

- alert: PktgatePktTruncated
  expr: rate(pktgate_lcore_pkt_truncated_total[5m]) > 0
  for: 5m
  annotations:
    summary: "truncated frames on lcore {{ $labels.lcore }} — check upstream MTU/cables"
```

### Deferred alerts (требуют Phase 2 wiring)

Метрики ниже объявлены в manifest'е, но **не** эмитятся в Phase 1
`/metrics` (см. `exposed: no` в таблицах выше). Alerts-шаблоны даны для
совместимости с будущим wiring'ом; **в текущем build'е эти expr вернут
no-data**.

```yaml
# НЕ ГОТОВО в Phase 1 — включать после phase 2 wiring.

# Требует lcore_cycles_per_burst histogram emit (manifest-only).
# Также нужен pktgate_tsc_hz gauge — сейчас tsc_hz кэшируется в WorkerCtx,
# метрикой не экспонируется. Альтернатива: забрать tsc_hz через
# dpdk-telemetry.py /eal/tsc_hz и использовать как константу recording-правила.
- alert: PktgateLatencyBudget
  expr: |
    histogram_quantile(0.99,
      rate(pktgate_lcore_cycles_per_burst_bucket[5m])
    ) * 1e9 / on() group_left() tsc_hz > 500000
  for: 2m
  annotations:
    summary: "p99 burst latency > 500µs (N2 SLO breach)"

# Требует mempool gauge emit (DPDK telemetry /mempool/info работает сейчас).
- alert: PktgateMempoolExhaustion
  expr: pktgate_mempool_free / (pktgate_mempool_in_use + pktgate_mempool_free) < 0.1
  for: 1m
  annotations:
    summary: "mempool <10% free — dataplane drops imminent"
```

## PromQL cookbook

Топ-5 rules по match rate:

```promql
topk(5, rate(pktgate_rule_packets_total[1m]))
```

Drop fraction per rule:

```promql
rate(pktgate_rule_drops_total[5m]) /
ignoring(rule_id) group_left sum(rate(pktgate_rule_packets_total[5m]))
```

RX-to-TX pipe efficiency (должен быть ~1 при идеальной пропускной):

```promql
rate(pktgate_port_tx_packets_total[1m]) /
rate(pktgate_port_rx_packets_total[1m])
```

Доля фрагментированного трафика (bump `drop`-политикой можно проверить
побочный эффект без перезапуска):

```promql
rate(pktgate_lcore_pkt_frag_skipped_total[5m]) +
rate(pktgate_lcore_pkt_frag_dropped_total[5m])
```

**Per-lcore load balance** (RSS-симметрия): `pktgate_lcore_packets_total`
в Phase 1 не wired — fallback через `pktgate_rule_packets_total` по
rule_id не работает (rule_id агрегирует через lcore'ы). До Phase 2 —
использовать `perf stat -e instructions` per-thread или DPDK telemetry
`/eal/lcore_list`.

## Формат экспорта

Standard Prometheus text exposition (OpenMetrics-compatible). `HELP` и
`TYPE` lines присутствуют для каждой family. Пример:

```
# HELP pktgate_rule_packets_total Matched packets per rule
# TYPE pktgate_rule_packets_total counter
pktgate_rule_packets_total{rule_id="1001"} 142857
pktgate_rule_packets_total{rule_id="1002"} 98765
# HELP pktgate_active_generation Current active ruleset generation
# TYPE pktgate_active_generation gauge
pktgate_active_generation 42
```

Histogram'ы пишут `_bucket{le="..."}`, `_count`, `_sum` по стандарту.
TSC-based bucket'ы для `lcore_cycles_per_burst` — bounds в cycles, не
в секундах (умножать на nanos/cycle для SI).

## Checklist после новой инсталляции

Первые 5 минут работы — что обязательно проверить в Grafana / prom:

- [ ] `pktgate_port_link_up == 1` на всех ожидаемых портах
- [ ] `rate(pktgate_port_rx_packets_total[1m]) > 0` — трафик приходит
- [ ] `rate(pktgate_rule_packets_total[1m]) > 0` — rules матчатся
- [ ] `rate(pktgate_port_rx_dropped_total[5m]) == 0` — нет backpressure
- [ ] `pktgate_active_generation > 0` и `pktgate_publisher_generation == pktgate_active_generation`
- [ ] `pktgate_lcore_dispatch_unreachable_total == 0` — no software bug hits
- [ ] mempool fill (через `dpdk-telemetry.py /mempool/info,pktgate_mbuf_pool`; gauge в `/metrics` — Phase 2)

Если один из пунктов красный — смотреть `docs/troubleshooting.md`.
