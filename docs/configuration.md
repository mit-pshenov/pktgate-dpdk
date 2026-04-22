# Configuration reference

Полный reference формата `config.json`. Источник истины —
`src/config/parser.cpp` + `src/config/validator.cpp` + `src/config/sizing.cpp`.
Схема строго whitelisted: любой неизвестный ключ — parse error с явным
именем поля. Silent-drop'ов нет, опечатка в имени поля валит загрузку.

Schema version: **1** (константа `kSchemaVersion`). Backcompat shim'ов нет —
pre-freeze, если изменим формат, version станет 2.

## Top-level schema

```json
{
  "version": 1,
  "interface_roles": { ... },
  "default_behavior": "allow|drop",
  "pipeline": {
    "layer_2": [ ... ],
    "layer_3": [ ... ],
    "layer_4": [ ... ]
  },
  "fragment_policy": "l3_only|drop|allow",
  "sizing": { ... },
  "objects": { "subnets": { ... } },
  "cmd_socket": { "allow_gids": [ ... ] }
}
```

| Поле | Обязательность | Дефолт | Семантика |
|---|---|---|---|
| `version` | required | — | Строгое равенство с `kSchemaVersion`. Mismatch → `kVersionMismatch`. |
| `interface_roles` | required | — | Role → DPDK port selector. Минимум 2 роли типичны (upstream/downstream). |
| `default_behavior` | required | — | Терминальный verdict при полном пролёте через pipeline. `allow` или `drop`. |
| `pipeline` | optional | пустые слои | Объект с массивами `layer_2` / `layer_3` / `layer_4`. Любой слой опционален. |
| `fragment_policy` | optional | `l3_only` | Поведение для IPv4/IPv6 фрагментов (non-first). |
| `sizing` | optional | dev-column | Runtime ёмкости (D6). При наличии секции — все 10 ключей required. |
| `objects` | optional | пусто | Pool именованных объектов (сейчас только `subnets`). |
| `cmd_socket` | optional | `allow_gids=null` | Настройки UDS control-socket. |

Неизвестный top-level ключ → `kUnknownField` с именем поля.

## interface_roles

Объект, ключи — имена ролей (любая строка, используется rules в поле
`interface`), значения — selector для DPDK порта. **Ровно один** из
`{pci, vdev, name}` на запись; zero или два+ → `kInvalidRoleSelector`.

```json
{
  "interface_roles": {
    "upstream":   {"pci": "0000:01:00.0"},
    "downstream": {"vdev": "net_tap0,iface=dtap0"},
    "bypass":     {"name": "net_vhost_bypass"}
  }
}
```

| Selector | Значение | Когда использовать |
|---|---|---|
| `pci` | `"0000:xx:yy.z"` | Production PCI NIC, bound к vfio-pci/uio. EAL whitelist'ит через `-a`. |
| `vdev` | `"net_tap0,iface=dtap0"` / `"net_vhost0,iface=/run/pktgate/vhost.sock"` | TAP / vhost-user profiles. Аргументы должны совпадать с `--vdev=` в EAL argv. |
| `name` | `"net_vhost0"` | Lookup по имени порта после probe'а. Use case редкий, обычно достаточно `vdev`. |

## pipeline и rules

Pipeline содержит три массива — `layer_2`, `layer_3`, `layer_4`. Каждый
массив — упорядоченный список rules. Порядок **значимый**: first-match-wins
внутри слоя.

### Правила layer transition

Pipeline — строго L2 → L3 → L4, без backward/same/skip. `next_layer` —
**явная advancement-директива**:

- Если поле **отсутствует** — rule **терминальный** на своём слое. Action
  применяется, пакет не идёт дальше. Это касается и `action: allow` —
  без `next_layer: "l3"` L2-ALLOW **не** передаёт пакет на L3.
- `layer_2` rule может нести `next_layer: "l3"` → продолжить в L3.
- `layer_3` rule может нести `next_layer: "l4"` → продолжить в L4.
- `layer_4` rule всегда терминальный; любой `next_layer` → `kInvalidLayerTransition`.
- Неправомерный `next_layer` (например, `"l3"` на L3 rule или `"l4"` на L2)
  → `kInvalidLayerTransition`.

**Типичная ошибка**: L2-rule с `action: allow` и без `next_layer` при
`default_behavior: drop` — пакет смэтчится, allow применится (терминально),
и **дальше не пойдёт**, но и не дропнется — см. invariant в `src/dataplane/classify_l2.cpp`.
Если L2-слой используется только для selectivity фильтра, а матч должен
делаться на L3/L4 — либо ставить `next_layer: "l3"` на L2-ALLOW, либо не
писать L2-правило вообще.

### Validation references

`dst_subnet` / `interface` в rules — **unresolved references**; валидатор
мэппит их на entry из `interface_roles` / `objects.subnets`. Dangling ref →
`kUnresolvedInterfaceRef` / `kUnresolvedObject`.

### Общая структура rule

```json
{
  "id": 1001,
  "interface": "upstream",
  "hw_offload_hint": false,

  // L2 match fields
  "src_mac": "aa:bb:cc:dd:ee:ff",
  "dst_mac": "11:22:33:44:55:66",
  "ethertype": 2048,
  "vlan_id": 100,
  "pcp": 5,
  "next_layer": "l3",

  // L3 match fields
  "dst_subnet": "whatsapp_cidrs",

  // L4 match fields
  "proto": 6,
  "src_port": 54321,
  "dst_port": 443,
  "dst_ports": [80, 443, 8443],
  "tcp_flags": { "syn": true, "ack": false },

  "action": { "type": "allow" }
}
```

| Поле | Тип | Bounds | Слой применимости |
|---|---|---|---|
| `id` | int | `[1, 2^31-1]`, уникален в scope pipeline | any (required) |
| `interface` | string | ref в `interface_roles` | any |
| `hw_offload_hint` | bool | — | any (D4 hint, MVP reject если не downgraded) |
| `src_mac` | string | `xx:xx:xx:xx:xx:xx` | L2 |
| `dst_mac` | string | `xx:xx:xx:xx:xx:xx` | L2 |
| `ethertype` | int | `[0, 65535]` (0x0800 IPv4, 0x86DD IPv6, 0x8100 VLAN, 0x88A8 QinQ) | L2 |
| `vlan_id` | int | `[0, 4095]` | L2 |
| `pcp` | int | `[0, 7]` | L2 |
| `next_layer` | enum | `"l2" \| "l3" \| "l4"` | L2/L3 |
| `dst_subnet` | string | ref в `objects.subnets` | L3 |
| `proto` | int | `[0, 255]` (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6) | L3/L4 |
| `dst_port` | int | `[0, 65535]` | L4 |
| `dst_ports` | int[] | каждый `[0, 65535]` | L4 |
| `src_port` | int | `[0, 65535]` | L4 |
| `tcp_flags` | object | см. ниже | L4 (proto=6 только) |
| `action` | object | см. ниже | any |

`dst_port` и `dst_ports` — взаимоисключающие на одном rule (валидатор).
Использовать `dst_ports` для набора портов (OR-семантика), `dst_port` для
единичного.

### tcp_flags

Объект, ключи — имена TCP флагов (lowercase), значения — boolean.

```json
"tcp_flags": { "syn": true, "ack": false, "fin": true }
```

Известные флаги: `fin, syn, rst, psh, ack, urg, ece, cwr`. Неизвестный ключ
→ `kUnknownField`. Семантика:

- **Ключ присутствует с `true`**: флаг должен быть установлен (match-if-set).
- **Ключ присутствует с `false`**: флаг должен быть сброшен (match-if-clear).
- **Ключ отсутствует**: don't-care.

Матчинг компилируется в `(tcp.flags & mask) == want` — zero-alloc на hot
path.

### Match semantics

First-match-wins **внутри слоя**; Ties по id не бывает (валидатор
эксплицитно ловит `kDuplicateRuleId`). Пустой слой = no matches = passthrough
в следующий слой (или terminal default).

L2 компилируется в compound key + filter_mask (`src_mac | dst_mac | vlan_id |
ethertype | pcp | interface`). «Don't care» поля занулены в mask. Не
конфликтует с порядком — при равных ключах первый выигрывает.

L3 использует rte_fib LPM на dst_subnet (CIDR); при CIDR-коллизии выигрывает
rule с наибольшим prefix length, при равных — с меньшим id (см. §P10(c) в
review-notes).

L4 — compound на `(proto, dst_port, src_port)` primary + filter_mask для
остальных (D15).

## Actions (verb details)

`action` — объект с дискриминирующим полем `type`. Whitelist полей
специфичен для каждого варианта, любое чужое поле → `kAmbiguousAction`.

### allow

```json
"action": { "type": "allow" }
```

Terminal accept. Пакет проходит через pipeline без модификаций, TX на
downstream port (per role в interface_roles).

### drop

```json
"action": { "type": "drop" }
```

Terminal drop. Пакет не доходит до TX, `pktgate_rule_packets_total` бампится,
mbuf освобождается.

### tag

```json
"action": {
  "type": "tag",
  "dscp": 46,
  "pcp": 5
}
```

Перезаписывает DSCP (IPv4 ToS / IPv6 TC) и/или PCP (VLAN tag). Оба поля
optional, bounds: `dscp [0, 63]`, `pcp [0, 7]`. Должен быть указан хотя бы
один, иначе no-op. **Не** terminal — если rule на L2/L3 и указан
`next_layer`, после tag пакет продолжает pipeline.

### target-port

```json
"action": {
  "type": "target-port",
  "target_port": "bypass"
}
```

Terminal redirect. Пакет идёт на role `target_port` из `interface_roles`
вместо дефолтного downstream. Dangling ref → `kUnresolvedTargetPort`.

### rate-limit

```json
"action": {
  "type": "rate-limit",
  "rate": "200Mbps",
  "burst_ms": 20
}
```

Token bucket per-lcore (D1, zero atomics). Пакет пропускается, если хватает
токенов; иначе drop.

- `rate`: `<int><kbps|Mbps|Gbps>`, case-sensitive. SI decimal (1 Mbps = 10^6
  bps). Parser конвертирует в bytes/sec на load time — hot path никогда не
  парсит строку.
- `burst_ms`: int > 0, мс. `burst_bytes = bytes_per_sec * burst_ms / 1000`.

Per-lcore bucket означает ~10-20% aggregate rate error при skewed RSS
(worst-case, D1 trade-off). Для equal-share distribution точность <5%.

### mirror

```json
"action": {
  "type": "mirror",
  "target_port": "mirror_sink"
}
```

Non-terminal mirror: пакет копируется на `target_port`, оригинал продолжает
pipeline. В Phase 2 — deep-copy; refcnt zero-copy — post-MVP (см.
`docs/limitations.md`). Back-pressure на slow consumer'е: после ~1k
accumulated тиков на mirror TX ring дропается копия (не оригинал), бамп
`pktgate_mirror_dropped_total`. См. `docs/observability.md`.

## default_behavior

```json
"default_behavior": "drop"
```

Terminal verdict для пакетов, прошедших **все** слои pipeline без матча.
`allow` — passthrough на downstream; `drop` — mbuf free. В обоих случаях
бампится `pktgate_default_action_total{action="allow"}` или
`pktgate_default_action_total{action="drop"}` соответственно.

В проде — практически всегда `drop` (zero-trust pre-filter перед DPI).

## fragment_policy

```json
"fragment_policy": "l3_only"
```

Поведение для IPv4 fragments (DF=0, non-zero offset) и IPv6 (Fragment
extension header, non-first). L4 header у non-first фрагмента отсутствует,
так что L4 matching невозможен — что с ним делать:

| Значение | Семантика для non-first фрагмента | Когда |
|---|---|---|
| `l3_only` (default) | **Skip L4 only.** L3 matching работает (`dst_subnet` whitelist применим); выставляется `SKIP_L4` flag на dynfield; pure-L3 rule всё ещё может terminate. | По умолчанию — консервативно, но позволяет L3-whitelist'у работать. |
| `drop` | Terminal drop на L3-стадии, бамп `pktgate_lcore_pkt_frag_dropped_total`. | Paranoid mode: untrusted uplink, любой fragmented UDP payload подозрителен. |
| `allow` | **Skip L2+L3+L4 целиком** → `kTerminalPass` на L3-стадии → применяется `default_behavior`. L3 matching **не** происходит. | Только когда реально нужно пропустить fragmented payload независимо от адресации. |

**Важно про `allow`.** Несмотря на имя, `allow` **не** мягче `l3_only`:
при `default_behavior: drop` pktgate дропнет non-first fragment ровно так
же, как `drop`-полиси (разница только в counter: `pkt_frag_*` не
бампнутся, будет только `pktgate_default_action_total{action="drop"}`).
Fragment пройдёт насквозь только при `default_behavior: allow` — и тогда
**любой** non-first fragment пройдёт, даже если его L3-адрес не в
whitelist'е. Для whitelist'а фрагментов по подсети используйте `l3_only`.

**First-fragment** (non-first = 0) полностью матчится, включая L4 — TCP/UDP
header в первом фрагменте присутствует.

## sizing

Runtime ёмкости rule/object pool'ов. **D6 anchor**: две first-class колонки
— `kSizingDevDefaults` (256/1024/256/…) и `kSizingProdDefaults`
(4096/16384/4096/…). Нет «MVP limit» phrasing — это dev-defaults vs
prod-defaults, обе equal-status.

Когда секции нет в config — используются `kSizingDevDefaults` (dev VM boots
zero-arg). Когда секция есть — **все 10 полей required**, silent
half-defaulting'а нет (любое missing → `kUnknownField`).

```json
"sizing": {
  "rules_per_layer_max":   4096,
  "mac_entries_max":       16384,
  "ipv4_prefixes_max":     4096,
  "ipv6_prefixes_max":     4096,
  "l4_entries_max":        4096,
  "vrf_entries_max":       256,
  "rate_limit_rules_max":  1024,
  "ethertype_entries_max": 128,
  "vlan_entries_max":      4096,
  "pcp_entries_max":       8,
  "prom_port":             9090
}
```

| Поле | Dev default | Prod default | Hard min |
|---|---|---|---|
| `rules_per_layer_max` | 256 | 4096 | **16** (D6 §3a.2) |
| `mac_entries_max` | 256 | 16384 | 0 |
| `ipv4_prefixes_max` | 1024 | 4096 | 0 |
| `ipv6_prefixes_max` | 1024 | 4096 | 0 |
| `l4_entries_max` | 256 | 4096 | 0 |
| `vrf_entries_max` | 32 | 256 | 0 |
| `rate_limit_rules_max` | 256 | 1024 | 0 |
| `ethertype_entries_max` | 32 | 128 | 0 |
| `vlan_entries_max` | 256 | 4096 | 0 |
| `pcp_entries_max` | 8 | 8 | 0 |
| `prom_port` | 9090 | 9090 | opt, `[0, 65535]` |

`rules_per_layer_max < 16` → `kSizingBelowMin` (не `kOutOfRange`, специальный
kind для operator-facing diagnostics).

`prom_port` — optional, не часть 10 required-полей. `0` → OS-assigned
ephemeral port (функциональные тесты используют чтобы избегать collision).

Валидатор делает pre-flight memory-budget check (D37) в три шага:

- `kBudgetPerRuleExceeded` — одно правило expand'ится во > ceiling
  entries (prevention: upstream rule explosion на wildcards).
- `kBudgetAggregateExceeded` — суммарная expansion > sizing cap
  соответствующего pool'а.
- `kBudgetHugepage` — оценочный RSS hashes + FIB + rl_arena
  превышает доступные hugepages.

## objects.subnets

Named CIDR pools для переиспользования в `dst_subnet`. IPv4 и IPv6 в одном
pool'е — первый успешный парсер выигрывает (IPv4 пробуется первым).

```json
"objects": {
  "subnets": {
    "whatsapp_v4": [
      "31.13.64.0/18",
      "157.240.0.0/16"
    ],
    "whatsapp_v6": [
      "2a03:2880::/32"
    ],
    "corp_nets": [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "fc00::/7"
    ]
  }
}
```

Пустая секция `objects: {}` — валидна (0 объектов). `subnets: {}` — тоже.

Невалидный CIDR литерал → `kBadCidr` с именем литерала. Пустое имя subnet
entry → `kUnknownField`.

Rule ссылается на subnet по имени:

```json
{
  "id": 2001,
  "dst_subnet": "whatsapp_v4",
  "action": {"type": "allow"}
}
```

Dangling reference → `kUnresolvedObject` на этапе валидатора.

**Note:** Поле называется `dst_subnet`, потому что L3 компилятор пакует CIDR
как destination prefix в rte_fib. Historical name был `src_subnet`,
переименован в P10(c) 2026-04-15. Backcompat shim'а нет — если в конфиге
осталось `src_subnet`, получите explicit deprecation error.

## cmd_socket

Настройки UDS control-socket (hot reload через signal + `allow_gids`
SO_PEERCRED auth, D38).

```json
"cmd_socket": {
  "allow_gids": [1000, 1001]
}
```

- `allow_gids` — массив integer GID'ов, которым разрешено писать reload-команды
  в socket. Элемент `[0, 2^32-1]`, negative → `kOutOfRange`.
- **Отсутствие ключа** (поле `null`) — означает «resolve at daemon init»;
  M11 валидация defer'ит решение, парсер не вызывает `getgid()` / `getgrnam()`.
- Пустой массив `[]` — никто не может писать команды (только root или owner).

Path UDS и прочие transport-params сейчас в CLI (`--ctl-sock`), а не в
config. Подробнее про hot reload — `docs/operations.md`.

## Полный пример config.json

Production-ish конфиг: 2 upstream + downstream + mirror sink, L3+L4
whitelist для WhatsApp CIDR, L4 rate-limit, default drop.

```json
{
  "version": 1,

  "interface_roles": {
    "upstream_port":   {"pci": "0000:01:00.0"},
    "downstream_port": {"pci": "0000:01:00.1"},
    "mirror_sink":     {"vdev": "net_vhost0,iface=/run/pktgate/mirror.sock,queues=1"}
  },

  "default_behavior": "drop",
  "fragment_policy":  "l3_only",

  "objects": {
    "subnets": {
      "whatsapp_v4": [
        "31.13.64.0/18",
        "157.240.0.0/16"
      ],
      "whatsapp_v6": [
        "2a03:2880::/32"
      ]
    }
  },

  "pipeline": {
    "layer_2": [
      {
        "id": 100,
        "ethertype": 2048,
        "next_layer": "l3",
        "action": {"type": "allow"}
      },
      {
        "id": 101,
        "ethertype": 34525,
        "next_layer": "l3",
        "action": {"type": "allow"}
      }
    ],

    "layer_3": [
      {
        "id": 200,
        "dst_subnet": "whatsapp_v4",
        "next_layer": "l4",
        "action": {"type": "allow"}
      },
      {
        "id": 201,
        "dst_subnet": "whatsapp_v6",
        "next_layer": "l4",
        "action": {"type": "allow"}
      }
    ],

    "layer_4": [
      {
        "id": 300,
        "proto": 6,
        "dst_port": 443,
        "tcp_flags": {"syn": true, "ack": false},
        "action": {
          "type": "rate-limit",
          "rate": "100Mbps",
          "burst_ms": 20
        }
      },
      {
        "id": 301,
        "proto": 6,
        "dst_port": 443,
        "action": {
          "type": "mirror",
          "target_port": "mirror_sink"
        }
      },
      {
        "id": 302,
        "proto": 6,
        "dst_ports": [443, 5222, 5223],
        "action": {"type": "allow"}
      },
      {
        "id": 303,
        "proto": 17,
        "dst_port": 3478,
        "action": {"type": "allow"}
      }
    ]
  },

  "sizing": {
    "rules_per_layer_max":   4096,
    "mac_entries_max":       16384,
    "ipv4_prefixes_max":     4096,
    "ipv6_prefixes_max":     4096,
    "l4_entries_max":        4096,
    "vrf_entries_max":       256,
    "rate_limit_rules_max":  1024,
    "ethertype_entries_max": 128,
    "vlan_entries_max":      4096,
    "pcp_entries_max":       8,
    "prom_port":             9090
  },

  "cmd_socket": {
    "allow_gids": [1000]
  }
}
```

Что делает этот конфиг:

1. L2: принимает только IPv4 (0x0800) и IPv6 (0x86DD), всё остальное падает в
   `default_behavior: drop`.
2. L3: на IPv4/v6 матчит только WhatsApp CIDR'ы; non-match → drop.
3. L4: 443/TCP SYN-without-ACK — rate-limit 100 Mbps; 443/TCP full flow —
   mirror на vhost-sink; 443/5222/5223/TCP и 3478/UDP (STUN) — allow; всё
   остальное → drop.
4. Mirror sink — vhost-user socket для peer'а DPI / IDS / pcap capture.
5. allow_gids=1000 — reload-команды может писать только user uid=1000.

## Parse errors

Полный список `ParseError::Kind` (см. `src/config/parser.h`). При провале
`pktgate_dpdk` пишет kind + message на stderr и exit'ится с кодом 1 до
EAL init:

| Kind | Триггер |
|---|---|
| `kJsonSyntax` | Невалидный JSON / number overflow |
| `kUnknownField` | Неизвестный ключ на любом уровне (strict whitelist) |
| `kTypeMismatch` | Тип не тот (int vs string и т.п.) |
| `kOutOfRange` | Число вне `[lo, hi]` |
| `kBadEnum` | Строковый enum не в allowed set |
| `kVersionMismatch` | `version != kSchemaVersion` |
| `kInvalidRoleSelector` | 0 или 2+ из `{pci, vdev, name}` |
| `kBadMac` | Невалидный MAC литерал |
| `kBadCidr` | Невалидный CIDR литерал |
| `kBadRate` | Rate literal не `<int><kbps\|Mbps\|Gbps>` |
| `kAmbiguousAction` | Action type discriminator отсутствует или в action есть не-whitelisted поле для данного type |
| `kSizingBelowMin` | `rules_per_layer_max < 16` |
| `kDuplicateRuleId` | Два rules с одним `id` в scope pipeline (валидатор) |
| `kKeyCollision` | Два L2-правила с идентичным compound key (D15) — валидатор |
| `kUnresolvedInterfaceRef` | `rule.interface` не нашлось в `interface_roles` (валидатор) |
| `kUnresolvedObject` | `rule.dst_subnet` не нашлось в `objects.subnets` (валидатор) |
| `kUnresolvedTargetPort` | `action.target_port` не нашлось в `interface_roles` (валидатор) |
| `kInvalidLayerTransition` | `next_layer` нарушает L2→L3→L4 monotonicity (валидатор) |
| `kBudgetPerRuleExceeded` | Одно правило expand'ится в entries > per-rule ceiling (D37 pre-flight) |
| `kBudgetAggregateExceeded` | Суммарный expansion превышает sizing cap соответствующего pool'а (D37) |
| `kBudgetHugepage` | Оценочный RSS hashes + FIB + rl_arena > доступные hugepages (D37) |

Валидация делится на **parser** (structural, single pass, без cross-ref) и
**validator** (cross-ref resolution, L2→L3→L4 order, memory budget, key
collision). Parser errors surface'ят конкретный ключ; validator errors —
конкретное правило (`rule id=NNN`).
