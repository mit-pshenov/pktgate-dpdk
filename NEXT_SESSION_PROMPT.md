# Инструкция для следующей сессии Claude

Привет, это записка от предыдущего тебя. Контекст в прошлой сессии
был на пределе, поэтому архитектурное ревью остановлено и все
артефакты положены сюда. Твоя задача — **не писать дизайн руками**,
а правильно запустить бригаду агентов (writer + reviewer) на batch
revision, собрать результат, показать пользователю.

## Шаг 0. Ориентация

Прочти в таком порядке:

1. `CLAUDE.md` — проектный гайд, M1/M2 принципы, свод D1-D20,
   рабочий процесс, границы автономии.
2. `input.md` — формализованные требования заказчика. Авторитетно.
3. `review-notes.md` — **самое важное**. Все decisions (D1-D20),
   pending (P7-P9), batch revision plan (24 шага). Источник истины
   по текущему состоянию дизайна.
4. `design.md` — пробежать оглавление (grep `^## `), читать
   выборочно по запросу. **Важно**: в секциях, где review-notes
   говорит «rewrite» или описывает критические баги, исходный текст
   **уже неверен** — не используй как основу для цитат или логики.

Не ныряй в design.md целиком — это 1100+ строк, выжжешь контекст,
а большая часть этих строк скоро будет переписана.

## Шаг 1. Разреши pending с пользователем

До запуска writer-а **обязательно** спроси пользователя по P8 и P9.
Они блокируют batch revision:

- **P8** — IPv6 ext-headers scope в MVP:
  - (a) парсить до K=2 hops (hop-by-hop, routing), дальше drop/pass
  - (b) first-proto only, ext-headers → v2
  - Мой lean: (b). Матчит «MVP as thin as we can» посыл и
    GGSN-Gi трафик всё ещё IPv4-dominant.

- **P9** — fragment policy default:
  - `drop` — architect's скрытый дефолт (его мы отменяем)
  - `l3_only` — применять L3-правила, пропускать L4, default
    action для L3-miss
  - `allow` — unsafe
  - Мой lean: `l3_only`.

- **P7** — rte_flow automatic topological offload promotion: v2
  или v3. **Не блокирует** batch revision (plan-level), можно
  спросить потом или оставить TBD в phase plan.

Задай вопрос одним сообщением, не тяни диалог. После ответа
обнови `review-notes.md`: P8→D20 резолюция, P9→D17 резолюция.
Зафиксируй как `## Resolution` под соответствующим D-блоком.

## Шаг 2. Запуск writer-агента

**Модель**: Opus (это архитектурная работа, Sonnet недостаточен на
плотных технических переписываниях C++/DPDK).

**Тип агента**: `general-purpose` (нужен write-доступ;
`Plan` — read-only, не подходит).

**Важно**: не запускай writer-а и reviewer-а параллельно —
reviewer-у нужен готовый design.v2.md на входе. Последовательно.

**Brief для writer** (скопировать целиком, включая тройные кавычки
в конце — это self-contained prompt):

```
You are revising the architecture document for pktgate-dpdk, a
greenfield DPDK-based L2/L3 packet filter for mobile operator
GGSN-Gi interfaces (40 Gbps, 500 µs latency budget, <0.01% loss).

WORKING DIRECTORY: /home/user/pktgate-dpdk/

READ FIRST (in this order, all three, no shortcuts):
  1. CLAUDE.md              — project guide, principles, decision log
  2. input.md               — customer requirements (authoritative)
  3. review-notes.md        — decision log D1-D20, batch revision
                              plan (24 steps), all the critique you
                              must apply
  4. design.md              — the v1 document you are revising

Do not start writing until you have read all four. design.md
contains known critical bugs identified in review-notes; treat any
section flagged there as "rewrite" as structurally unsound.

YOUR TASK: produce design.v2.md in the same directory by applying
every step of the "Batch revision plan" in review-notes.md
(currently 24 steps, D1 through D20 plus structural passes M1/M2).

HARD RULES:
  1. M2 structural pass FIRST. Before touching any content, grep
     for "MVP", "v2", "Phase", "in the future" in sections §1-§13
     and move every one of those out into §14 Phase plan. This is
     non-negotiable and must be step 1 of your execution — doing it
     last leaves contamination.

  2. M1 principle: dev VM characteristics (Intel e1000, 512 MB
     hugepages, single-queue) must NOT shape architecture. The
     doc describes the target system. Dev limitations belong in a
     separate "dev defaults vs production targets" table, not as
     architectural constraints.

  3. Do not overwrite design.md. Write to design.v2.md. Keep v1
     intact for diff review.

  4. Apply decisions exactly as specified in review-notes. Do not
     "optimize" or "improve" them — they are the output of a
     resolved discussion. If you find a genuinely new issue
     during writing, note it in a "## Writer notes" appendix at
     the end of design.v2.md; do not silently change behavior.

  5. For D9 (global g_active): single atomic pointer in a
     process-wide control struct, not per-WorkerCtx. Remove the
     field from WorkerCtx entirely. Hot path does one
     acquire-load per burst into a local const Ruleset* rs.

  6. For D10 (per-lcore rate-limit): rewrite §4.4 and §5.5
     exactly as described in review-notes D10, including the
     two-level mapping (ruleset rl_index → rule_id → arena row →
     TokenBucket[RTE_MAX_LCORE]). Zero atomics on the hot path.

  7. For D15 (L4 compound matching): §4.1 L4 structures and §5.4
     classifier must mirror the L2 compound primary + filter_mask
     pattern. Primary hashes on (proto | dport), (proto | sport),
     (proto); secondary filter_mask on sport / sport_range /
     tcp_flags. Ranges are plan-phase non-goal for MVP.

  8. For D13 (L3 offset bug): add an l3_offset byte to the mbuf
     dynfield, set in §5.2 L2 parse, consumed in §5.3/§5.4. This
     replaces the buggy `et == 0x8100 ? 18 : 14` ternary.

  9. Pending resolutions in review-notes are authoritative — if
     the user has resolved P8 and P9 before you start, those
     answers will be in review-notes as "## Resolution" blocks
     under D20 and D17. Apply them. If P8/P9 are still unresolved
     when you start, STOP and report back to the parent — do not
     guess.

 10. C++20 baseline, C++23 idioms welcome (D2). Compiler choice
     at implementer discretion (gcc ≥ 14 or clang ≥ 18).

DELIVERABLES:
  - design.v2.md in /home/user/pktgate-dpdk/
  - At the end of the file, a "## Writer notes" appendix listing:
    * every batch-revision step you applied (by number and
      decision ID)
    * any step you skipped and why
    * any new issues you spotted while writing (do not fix, just
      flag)
  - A final one-paragraph summary of the diff scope for the
    parent.

Do NOT:
  - touch input.md (that is the customer contract)
  - touch review-notes.md (that is the next agent's input)
  - delete design.md (v1 must stay for diff)
  - refactor things that are not in the batch revision plan
  - introduce new abstractions, helpers, or "while we're here"
    improvements
  - write implementation code (C++) — this is still architecture,
    the code blocks are pseudocode for spec clarity only

Report back with: path to design.v2.md, summary of what changed,
any flags for the reviewer.
```

## Шаг 3. Запуск reviewer-агента

Запускать **после** того как writer вернулся и ты убедился, что
`design.v2.md` реально существует и не обрезан.

**Модель**: Opus (снова — архитектурный review требует держать в
голове много абстракций сразу).

**Тип агента**: `general-purpose`, отдельный свежий instance.
**Не** передавай ему контекст writer-а — reviewer должен смотреть
независимо.

**Brief для reviewer**:

```
You are the independent reviewer for the pktgate-dpdk architecture
document revision. A writer agent has produced design.v2.md by
applying a batch revision plan to design.md (v1). Your job is to
verify the revision is correct, complete, and did not introduce
new bugs.

WORKING DIRECTORY: /home/user/pktgate-dpdk/

READ (in this order):
  1. CLAUDE.md         — project guide, M1/M2 principles
  2. input.md          — customer requirements (authoritative)
  3. review-notes.md   — the decision log the writer was given.
                          D1-D20 are the decisions; the "Batch
                          revision plan" section (24 steps) is
                          what the writer was told to apply.
  4. design.v2.md      — the writer's output. Read fully.
  5. design.md         — only if you need to cross-reference
                          specific sections to see what changed.
                          Do NOT read fully — you will run out of
                          context.

YOUR CHECKS:

A. Completeness — was every decision applied?
   For each D1 through D20, find the corresponding content in
   design.v2.md and verify it matches the decision's specification
   in review-notes. Produce a table:
   | Decision | Applied? | Section(s) in v2 | Notes |
   Mark "partial" if the decision is visible but not fully
   realized (e.g., mentioned in text but code block still shows
   old pattern).

B. M1/M2 structural compliance.
   - grep design.v2.md for "MVP", "v2", "Phase", "in the future",
     "for now", "later". Every hit in §1-§13 is an M2 violation.
     Report all of them with section and line.
   - Find any passage that cites dev VM limitations (e1000,
     single-queue, 512 MB hugepages) as a reason for an
     architectural choice. Those are M1 violations.

C. Critical bug regression checks.
   Specifically re-verify these previously-identified bugs are
   actually fixed, not just mentioned:
   - D9: Is there a single atomic g_active pointer used by both
     writer (reload) and readers (workers)? Is the field removed
     from WorkerCtx? Does the hot-path pseudocode load from the
     global, not from ctx?
   - D10: Does §4.4 show per-lcore TokenBucket arrays, zero
     atomics, arena keyed by rule_id? Does §5.5 RL case use
     rte_lcore_id() indexing with no CAS loop?
   - D13: Is there an l3_offset byte in the dynfield, set by L2
     parse, consumed by L3/L4 classifiers? Does the old
     `et == 0x8100 ? 18 : 14` ternary exist anywhere?
   - D14: Does L4 classifier compute L4 offset via IHL, not
     hard-coded 20?
   - D15: Does §4.1 L4 structures show multiple primary hashes
     + L4CompoundEntry filter_mask? Does §5.4 classifier call
     them in selectivity order like §5.2 L2 does?
   - D16: Does REDIRECT have per-port staging and burst-end
     flush with unsent-mbuf free?
   - D17: Is fragment_policy a configurable field, not a
     hard-coded drop?

D. New bug hunt.
   Read §4 data structures and §5 hot path walkthrough carefully.
   Look for:
   - use-after-free / data-race hazards
   - off-by-one in header offset calculations
   - missing null checks on lookup returns
   - action dispatch paths that don't free mbufs on failure
   - RCU protocol violations (references held across quiescent)
   - cache line false sharing (writable fields sharing a line
     with hot reads)
   - cycle budget claims that don't add up

E. Cross-section consistency.
   Things the v1 review missed: §3 module list vs §13 project
   structure vs §14 phase plan — do they reference the same
   component names? Does §10 telemetry list metrics that §4
   actually exposes? Does §11 failure modes reference states
   that §6 lifecycle actually has?

DELIVERABLES:

Write your report to /home/user/pktgate-dpdk/review-v2.md with
this structure:

  # Review of design.v2.md

  ## Verdict
  One of: APPROVE / APPROVE_WITH_FIXES / REVISE / REJECT
  One-paragraph justification.

  ## A. Decision application table
  [table per check A]

  ## B. M1/M2 violations
  [list or "none found"]

  ## C. Critical bug regression
  [per-bug status]

  ## D. New issues
  [numbered list, severity: critical / medium / minor]

  ## E. Consistency issues
  [list or "none found"]

  ## Recommended next action
  What should the parent tell the user to do next.

HARD RULES:
  - Do not edit design.v2.md yourself. You are a reviewer.
  - Do not re-litigate resolved decisions (D1-D20 are not open
    for debate — only check whether they are correctly applied).
  - If you disagree with a resolved decision, note it in "D. New
    issues" at "minor" severity as a dissent, do not block the
    review on it.
  - Be specific: every finding must cite a file and a section or
    line number.
  - Be concise: the report is read by a human who will act on it.
    Prefer tables and bullet lists over prose.

Report back with: path to review-v2.md, verdict, count of
critical/medium/minor issues.
```

## Шаг 4. После возврата reviewer-а

1. Прочти `review-v2.md` целиком (он должен быть короткий).
2. Покажи пользователю **verdict + сводку критических находок**
   (не весь файл, только summary). Пользователь решает:
   - **APPROVE / APPROVE_WITH_FIXES** → переименовать design.v2.md
     в design.md (после подтверждения пользователя), обновить
     review-notes (пометить batch revision как применённый),
     перейти к следующей фазе (impl plan или §3 project structure
     ревью).
   - **REVISE** → второй круг writer-а с reviewer-отчётом как
     дополнительным входом. **Scope только конкретные секции**, не
     полный пересмотр. Новый файл: design.v3.md.
   - **REJECT** → серьёзный структурный сбой, нужен разговор с
     пользователем перед любыми дальнейшими действиями.
3. Если нашлись новые critical-баги класса D9/D15 (т.е. writer
   сломал что-то новое) — запиши их в `review-notes.md` как
   D21+, не пытайся чинить самостоятельно.

## Anti-patterns — чего НЕ делать

- **Не редактируй design.md руками.** Даже «мелкую правку». Любое
  изменение → через агента. Single source of truth — важнее
  скорости.
- **Не запускай writer без reviewer.** Одна голова систематически
  пропускает structural issues. Именно так появились D9, D15, D17
  в v1 (Plan-агент писал в одиночку).
- **Не запускай writer+reviewer одной моделью в одном сообщении
  параллельно.** Reviewer должен смотреть на финальный output
  writer-а, не на промежуточный.
- **Не давай reviewer-у контекст writer-а.** Независимость отчёта
  критична. Freshly-spawned agent, минимум информации, максимум
  собственной работы.
- **Не расширяй scope агентов.** Если reviewer нашёл новый баг —
  это работа следующего круга, не текущего writer-а.
- **Не коммить в git автоматически.** Правило проекта: git
  операции только по явной просьбе пользователя.
- **Не трогай sibling `/home/user/filter/`.** Это другой проект.

## Если что-то пошло не так

- **Writer завершился с усечённым файлом** (design.v2.md подозрительно
  короткий, < 500 строк) → не запускай reviewer. Переспроси writer-а
  с просьбой продолжить с того места, где остановился, либо
  перезапусти целиком.
- **Reviewer не смог прочитать файлы** → проверь пути, проверь права.
- **Reviewer вынес REJECT** → не запускай второй круг writer-а
  молча. Покажи пользователю, он решает.
- **Контекст у тебя кончается** → **остановись**, сохрани состояние
  в `review-notes.md` как новую секцию `## Session handoff N`,
  попроси пользователя закрыть сессию и продолжить в следующей.
  Не пытайся дотянуть «ещё чуть-чуть» — именно так я сжёг контекст в
  прошлый раз.

## Быстрый sanity-check перед запуском

- [ ] Прочитал CLAUDE.md, input.md, review-notes.md
- [ ] Отсканировал оглавление design.md (grep `^## `)
- [ ] Спросил пользователя про P8 и P9
- [ ] Обновил review-notes с резолюциями P8/P9
- [ ] Запустил writer (Opus, general-purpose, НЕ параллельно с ревьюером)
- [ ] Дождался design.v2.md, проверил что не усечён
- [ ] Запустил reviewer (Opus, general-purpose, свежий instance)
- [ ] Прочитал review-v2.md, показал пользователю verdict
- [ ] Действую по решению пользователя

Удачи. Самая частая ошибка — экономить на reviewer-е («writer же
умный, и так сойдёт»). Не экономь. Это единственный способ поймать
D9-класс багов до того, как они доживут до импла.
