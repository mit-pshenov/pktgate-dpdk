# pktgate-dpdk — project guide

Проектный контекст и рабочие договорённости для будущих сессий и
агентов. Дублировать сюда сами решения не нужно — они живут в
`review-notes.md`. Это файл-навигатор.

## Что это

Greenfield L2/L3 packet filter на DPDK для GGSN-Gi интерфейсов
мобильного оператора. Работает inline как pre-filter перед WhatsApp
DPI. Таргет — 40 Gbps per site, ≤500 µs latency overhead, <0.01%
loss. Заказчик дал требования, они формализованы в `input.md`.

**Sibling, не fork** `/home/user/filter` (pktgate, XDP/eBPF). Код
не переиспользуем — слишком жёсткая связь с BPF. Переносим только
семантические уроки (first-match-wins, compound L2, fragment
handling, dual-stack). Schema compat с pktgate JSON — **дропнута
полностью** (D8). Сценарии в `~/filter/scenarios/` — только
источник вдохновения для тестов.

## Артефакты

| Файл | Что внутри | Как читать |
|---|---|---|
| `input.md` | Формализованные требования заказчика, F1-F7 / N1-N5 / constraints / non-goals / 16 expected deliverables | Авторитетно. Меняется только через явное согласование с заказчиком (через пользователя). |
| `design.md` | Архитектурный док (17 секций + summary), написан Plan-агентом на Opus. **Содержит известные баги** — см. review-notes. | Читать вместе с review-notes. Не цитировать §4.1/§4.4/§5.3/§5.4/§9.2 как истину — там критические дефекты. |
| `review-notes.md` | Мета-принципы (M1-M2), решения (D1-D20), pending (P7-P9), batch revision plan (24 шага) | Источник истины по текущему состоянию дизайна. Каждое D-решение перекрывает соответствующий кусок design.md. |

**Состояние design.md**: первая версия, прошла два ревью-прохода
(§9 hot reload и §5 hot path). Ждёт batch revision, после которого
станет консистентной.

## Мета-принципы

**M1 — Dev VM это песочница.**
Виртуалка для разработки (VirtualBox, Intel 82545EM e1000, 512 MB
hugepages) **не должна формировать архитектуру**. Примеры: симметричный
Toeplitz RSS остаётся в дизайне, хотя e1000 его не умеет (на деве
деградируем до single-queue). Параметры ёмкости (кол-во правил,
количество очередей, размер hugepages) имеют dev-дефолты и
production-таргеты — это **две разные колонки в таблице**, а не «MVP
ограничен до dev-сайзов».

**M2 — Архитектура ≠ план.**
Архитектурные секции описывают целевую систему. Фразы вида «MVP
использует X, v2 переходит на Y» **запрещены в секциях §1-§13**.
Любое «что отгружаем в какой фазе» идёт в §14 Phase plan. Перед
коммитом ревью-прохода: grep по "MVP", "v2", "Phase" в arch-секциях.

## Рабочий стиль

Проектные дополнения к глобальному `~/.claude/CLAUDE.md`:

- **Честность про контекст**. Если окно заполнено — сказать, не
  продолжать на парах.
- **Push proactively**. Если нашёл баг — пушить находку, не ждать
  явной просьбы («проверь вот это»).
- **Архитектура обсуждается до кода**. Сначала review → decision →
  batch revision → тогда импл. Не начинать писать C++ пока design.md
  не консистентен.
- **Критика предыдущего прохода — нормально**. Plan-агент писал на
  Opus с ограниченным контекстом и ошибался (см. D9-D20). Следующие
  проходы — переписать, не «оптимизировать».
- **Decisions кумулятивны**. Новое решение может отменить старое —
  тогда явно помечается в review-notes: «D10 overrides part of
  architect's §4.4». Не молча.
- **Внешние ревьюеры — НЕ авторитет по DPDK API**. Любая claim
  вида «DPDK делает X», «функция Y принимает Z», «параметр W
  это TSC delta» обязана быть верифицирована через
  `doc.dpdk.org/api-<version>/` ДО внесения в design.md. Прецедент:
  D30 — третий ревью продал нам неправильный фикс
  `rte_rcu_qsbr_check` ("принимает TSC delta"), мы взяли без
  проверки, четвёртый ревью обнаружил. Hearsay ≠ fact.

## Remote dev VM

- **Хост**: `ssh dpdk` (Fedora, sudo без пароля)
- **DPDK**: 25.11, установлен, `pkg-config libdpdk` работает
- **Hugepages**: 512 × 2 MB, uio/vfio модули загружены
- **NIC**: Intel 82545EM (e1000), **DPDK-совместимый через vfio-pci**,
  но single-queue, без RSS, без TSO. Песочница, не прод-нагрузка.
- **Рабочий каталог на VM**: `~/Dev/pktgate-dpdk/` (туда синкали
  input.md / design.md / review-notes.md в прошлой сессии)

## Production targets

Дизайн держать в уме эти NIC при проверках (rte_flow API,
capability bits, queue count):

- Intel E810 (ice driver)
- Intel XL710 (i40e)
- Mellanox ConnectX-5 / ConnectX-6 (mlx5)

## Ключевые зафиксированные решения (свод)

Полные формулировки — в `review-notes.md`. Здесь только якоря для
быстрого поиска.

| ID | Тема | Статус |
|---|---|---|
| **M1** | Dev VM не формирует архитектуру | Принят |
| **M2** | Arch ≠ Plan separation | Принят |
| **D1** | Per-lcore token bucket, zero atomics | Принят, overrides §4.4 |
| **D2** | C++20 baseline, C++23 welcome, gcc≥14 или clang≥18 | Принят |
| **D3** | Telemetry: полная модель подсчёта в архитектуре, выбор каналов → в §14 | Принят |
| **D4** | rte_flow hw offload: архитектурные хуки (rule tiering, dual-path), MVP ships disabled | Принят |
| **D5** | HA compatibility: interface_roles, `--standby`, anti-patterns forbidden | Принят |
| **D6** | Rule count параметризуется runtime, dev vs prod как две колонки | Принят |
| **D7** | Mirror: полная семантика в архитектуре, MVP — компилятор reject | Принят |
| **D8** | Drop pktgate schema compat полностью | Принят |
| **D9** | Single global `g_active`, remove from WorkerCtx (fix UAF) | Принят, overrides §4.2/§5.1/§9.2 |
| **D10** | Rewrite §4.4/§5.5 per D1 (per-lcore bucket arena) | Принят |
| **D11** | rl_arena GC ordering after synchronize | Принят |
| **D12** | RCU polish: shutdown offline/unregister, synchronize timeout | Принят |
| **D13** | L3 offset fix для VLAN-tagged: `l3_offset` byte в dynfield | Принят, critical bug fix |
| **D14** | L4 offset через IHL, IPv6 ext-header scope | Принят, critical bug fix |
| **D15** | Rewrite L4 matching: compound primary + filter_mask (как L2) | Принят, critical structural fix |
| **D16** | REDIRECT staging + burst-end flush | Принят |
| **D17** | `fragment_policy` config field (не хардкод drop) | Принят |
| **D18** | Cycle budget §5.6 min/typ/max вместо только best case | Принят |
| **D19** | Misc: fib_lookup single vs bulk-1, handle_idle spec, TAG semantics | Принят |
| **D20** | IPv6 ext-headers MVP scope — pending (см. P8) | Зависит от P8 |
| **D21** | Fix NEXT_L4 cliff in §5.3 (verdict=NEXT_L4 must not skip L4) | Принят, critical bug fix |
| **D22** | RuleAction sizing: 20 B + alignas(4), не 64 B | Принят (in-place, см. также 2-й внеш. ревью) |
| **D23** | NUMA awareness в Ruleset/Workers — explicit | Принят |
| **D24** | rl_arena slot lifecycle: free slot, не free row | Принят |
| **D25** | apply_action default arms + -Wswitch-enum | Принят |
| **D26** | Mirror refcnt-zero-copy compile-time gate (MUTATING_VERBS) | Принят, 1-й внеш. ревью |
| **D27** | IPv6 fragment first vs non-first differentiation, l4_extra dynfield | Принят, critical bug fix, 2-й внеш. ревью |
| **D28** | Dataplane port TX-queue symmetry invariant (n_workers на каждом порту) | Принят, 2-й внеш. ревью |
| **D29** | Drop dead `want_icmp_code` field из L4CompoundEntry | Принят, 2-й внеш. ревью |
| **D30** | Fix `rte_rcu_qsbr_check` misuse: token + explicit deadline (НЕ TSC delta), bundled API renames | Принят, embarrassing fix, 4-й (5-lawyer) ревью |
| **D31** | Truncation guards в §5.2/§5.3/§5.4 + `pkt_truncated_total[where]` counter | Принят, 4-й ревью |
| **D32** | QinQ 0x88A8 outer accept в §5.2 + `qinq_outer_only_total` counter | Принят, 4-й ревью |
| **D33** | Counter consistency invariant: §10.3 = source of truth (закрыты dangling refs) | Принят, 4-й ревью |
| **D34** | rl_arena refill `elapsed` clamp at `tsc_hz` (overflow на idle) | Принят, 4-й ревью |
| **D35** | Single `g_cp.reload_mutex` covering все reload entry points (inotify + cmd_socket + telemetry) | Принят, 4-й ревью |
| **D36** | `pending_free` queue для reload-timeout path | Принят (bundled с D30), 4-й ревью |
| **D37** | Validator memory-budget pre-flight + per-rule expansion ceiling | Принят, 4-й ревью |
| **D38** | SO_PEERCRED на UDS + IN_CLOSE_WRITE-only inotify | Принят, 4-й ревью |

## Pending (требуют решения пользователя)

- **P7** — rte_flow automatic topological offload promotion: v2 или v3? (plan-level, не блокирует batch revision)
- **P8** — IPv6 ext-headers scope в MVP: (a) до K=2 hops, (b) first-proto only, ext в v2. Мой lean: (b).
- **P9** — fragment policy default: `drop` / `l3_only` / `allow`. Мой lean: `l3_only`.

## Non-goals (что **не** делаем)

Из `input.md` §4, плюс то что добавилось по ходу:

- DPI, L7 parsing, protocol dissection
- TLS fingerprinting, JA3/JA4
- Flow tracking, connection state (per-flow state only для v2 rate-limit)
- Encryption / decryption
- Packet modification за пределами DSCP/PCP rewrite (TAG action)
- NAT, proxying, L7 routing
- IPS/IDS сигнатурный матчинг
- Schema compat с pktgate JSON (D8)
- Reuse pktgate kernel/BPF кода
- Ускоренная разработка за счёт архитектурной чистоты

## Рабочий процесс для следующей сессии

Следующий шаг — **batch revision design.md**. Запускать агентскую
бригаду, не делать in-place руками:

1. **Writer-агент** (Opus, Plan или general, с read-write доступом
   в `/home/user/pktgate-dpdk/`):
   - Вход: `input.md`, `design.md`, `review-notes.md` (все три
     должны быть прочитаны ДО начала правок).
   - Задача: применить batch revision plan из review-notes (24
     шага), выдать новый `design.md` v2.
   - Критически важно: **M2 structural pass** (шаг 1) идёт
     первым — иначе правки смешаются с старыми MVP/v2
     формулировками и получится каша.
2. **Reviewer-агент** (Opus, отдельный — не тот, что писал):
   - Вход: `design.md` v2, `review-notes.md`, `input.md`.
   - Задача: проверить что все D1-D20 реально применены, что M1/M2
     соблюдены, что не появилось новых багов класса D9/D13/D15.
     Выдать diff-анализ.
3. **Я** (основной чат):
   - Читаю diff reviewer-а.
   - Принимаю / отклоняю правки, обновляю review-notes.
   - Если найдены новые критические баги — второй круг
     writer+reviewer по конкретной секции.

**Не запускать writer без reviewer.** Одна голова (даже Opus)
систематически пропускает structural issues — именно так появились
D9, D15, D17. Две головы с разделёнными ролями ловят на порядок
больше.

## Границы автономии

- **Root/sudo на деве** — свободно, без вопросов.
- **Правки в `/home/user/pktgate-dpdk/`** — свободно, это проект.
- **Правки в `/home/user/filter/`** — только по явной просьбе, это
  sibling-проект.
- **Git init / commit / push** — только по явной просьбе.
- **Синк на `ssh dpdk`** — свободно в `~/Dev/pktgate-dpdk/`.
- **Запуск DPDK-приложений с root** — свободно на деве, после
  первого импла.

## Быстрая ориентация для нового агента

Если ты агент, которого только что подняли в этом каталоге:

1. Прочти `input.md` целиком — это требования.
2. Прочти `review-notes.md` целиком — это текущее состояние решений.
3. Прочти `design.md` **по секциям**, сверяясь с review-notes: в
   каждой секции где review-notes говорит «rewrite», исходный текст
   **уже неверен** — не используй его как basis.
4. Если тебе дали задачу «писать» или «ревьюить» — делай ровно то,
   что тебе сказали. Не расширяй scope.
5. Результат клади в тот же каталог, под версионированным именем
   (например `design.v2.md`) — не перетирай оригинал без явной
   отмашки.
