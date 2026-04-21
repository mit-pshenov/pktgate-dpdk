# Observability

Prometheus `/metrics` reference. 41 счётчика, сгруппированы по семействам
(rule / port / lcore / dispatch / reload / system / watchdog). Источник
истины — `src/telemetry/counter_names.h` (константы `kAllCounterNames`).

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
counter'ы pktgate'а (D43).

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
| `pktgate_lcore_packets_total` | C | `lcore` | Пакетов обработано этим worker'ом. Sanity: sum по всем lcore ≈ sum(`port_rx_packets`). |
| `pktgate_lcore_cycles_per_burst` | H | `lcore` | TSC cycles / burst. SLO-критический. Buckets рассчитаны чтобы p99 < 500µs (N2 требование). Attention: p99 > 500µs → latency overhead outside budget. |
| `pktgate_lcore_idle_iters_total` | C | `lcore` | Итераций RX loop'а с `rx_burst=0`. Высокий idle ratio = lightly loaded lcore; низкий → close to saturation. |
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
| `pktgate_reload_latency_seconds` | H | — | Время от deploy() до publish (включая QSBR synchronize). p99 norm <100ms. Attention: >1s → QSBR timeout, worker stuck. |
| `pktgate_reload_pending_free_depth` | G | — | Количество отложенных освобождений (timeout path). Norm = 0. Sustained >0 → worker died mid-reload или live-lock. |
| `pktgate_active_generation` | G | — | Generation живого ruleset'а (monotonic increment on successful reload). Exposition — для debugging. |
| `pktgate_active_rules` | G | `layer` | Количество rules в каждом слое текущего generation'а. |
| `pktgate_cmd_socket_rejected_total` | C | `reason` | cmd_socket запрос отклонён (bad verb, auth fail в future peercred build). |
| `pktgate_publisher_generation` | G | — | Последняя generation которую publisher thread **видел**. Invariant: `publisher_generation == active_generation` после QSBR settle. Growing gap → publisher stuck. |

## Системные gauge'и (2)

| Name | Type | Labels | Семантика / триггер внимания |
|---|---|---|---|
| `pktgate_mempool_in_use` | G | — | mbuf'ов выдано NIC RX ring'ам. Attention: растёт к capacity → underprovisioned mempool, `rx_dropped` скоро начнёт бампаться. |
| `pktgate_mempool_free` | G | — | Free mbuf'ы. Invariant: `in_use + free ≈ mempool_size`. |

## Watchdog / bypass / log (3)

| Name | Type | Labels | Семантика / триггер внимания |
|---|---|---|---|
| `pktgate_watchdog_restarts_total` | C | — | Count рестартов worker thread'а watchdog'ом (**M12 deferred** — в Phase 1 build присутствует как zero placeholder). |
| `pktgate_bypass_active` | G | — | `1` если pktgate в bypass mode (kernel-route через ВТ host). **M12 deferred**. |
| `pktgate_log_dropped_total` | C | — | JSON events dropped в ring-buffer fallback (если stdout writer залипнет). Baseline zero. |

## SLO mapping (N1-N5 из input.md)

| SLO | Target | Key metric |
|---|---|---|
| N1 — throughput | 40 Gbps per site | `rate(port_rx_bytes[1m])` + `rate(port_tx_bytes[1m])` |
| N2 — p99 latency | ≤500 µs overhead | `histogram_quantile(0.99, rate(lcore_cycles_per_burst_bucket[5m]))` × nanos-per-cycle |
| N3 — packet loss | <0.01% | `rate(port_rx_dropped[5m]) / rate(port_rx_packets[5m])` |
| N4 — reload latency | ≤500 ms | `histogram_quantile(0.99, rate(reload_latency_seconds_bucket[10m]))` |
| N5 — availability | 99.9% | `pktgate_port_link_up == 1` + `up{job="pktgate"}` |

## Recommended alerts

```yaml
# Prometheus rules примеры.

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

- alert: PktgateReloadFailing
  expr: rate(pktgate_reload_total{result!="success"}[5m]) > 0
  for: 2m
  annotations:
    summary: "Reloads failing (kind={{ $labels.result }})"

- alert: PktgateLatencyBudget
  expr: |
    histogram_quantile(0.99,
      rate(pktgate_lcore_cycles_per_burst_bucket[5m])
    ) * 1e9 / pktgate_tsc_hz > 500000
  for: 2m
  annotations:
    summary: "p99 burst latency > 500µs (N2 SLO breach)"

- alert: PktgateMirrorBackpressure
  expr: rate(pktgate_mirror_dropped_total[5m]) > 0
  for: 5m
  annotations:
    summary: "Mirror peer slow — clones dropped on {{ $labels.target_port }}"

- alert: PktgateMempoolExhaustion
  expr: pktgate_mempool_free / (pktgate_mempool_in_use + pktgate_mempool_free) < 0.1
  for: 1m
  annotations:
    summary: "mempool <10% free — dataplane drops imminent"

- alert: PktgateUnreachableBranch
  expr: increase(pktgate_lcore_dispatch_unreachable_total[5m]) > 0
  for: 0s
  annotations:
    summary: "software bug — dispatch unreachable branch hit on lcore {{ $labels.lcore }}"
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

Per-lcore load balance (должен быть ровный при symmetric RSS):

```promql
rate(pktgate_lcore_packets_total[1m])
```

Skew > 20% между lcore'ами → RSS key не симметричный или hot flow на одной очереди.

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
- [ ] `pktgate_mempool_in_use < 0.7 * mempool_size` — запас под burst'ы

Если один из пунктов красный — смотреть `docs/troubleshooting.md`.
