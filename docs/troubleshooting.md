# Troubleshooting

Симптом → возможные причины → диагностические команды. Организован по
фазам: boot → dataplane → control plane → shutdown.

## Boot stage — процесс не стартует

### `Cannot map hugepages` / `No free 2048 kB hugepages reported on node 0`

**Причина.** Hugepages не аллоцированы, либо уже заняты другим DPDK-процессом.

**Диагностика.**

```bash
cat /proc/meminfo | grep Huge
# HugePages_Total должен быть > 0
# HugePages_Free должен быть ≥ тому что просит --socket-mem / defaults

ls -la /dev/hugepages  # mount point должен существовать
mount | grep hugetlbfs
```

**Fix.** `sudo bash scripts/dev_hugepages.sh` (dev VM), или persistent через grub
(см. `docs/install.md` §Hugepages). Для prod — 1G pages рекомендуются:

```bash
# /etc/default/grub:
# GRUB_CMDLINE_LINUX="... default_hugepagesz=1G hugepagesz=1G hugepages=8"
sudo grub2-mkconfig -o /boot/grub2/grub.cfg && sudo reboot
```

---

### `EAL: Detected 0 PCI devices` / `No Ethernet ports available`

**Причина.** NIC не bind'нут к vfio-pci / uio_pci_generic, либо `-a` EAL аргумент промахнулся по BDF.

**Диагностика.**

```bash
sudo dpdk-devbind.py --status
# Ищем раздел "Network devices using DPDK-compatible driver"
# Если NIC в "kernel driver" секции — не bind'нут
```

**Fix.**

```bash
sudo modprobe vfio-pci
sudo ip link set <iface> down     # уронить kernel netdev
sudo dpdk-devbind.py -b vfio-pci 0000:01:00.0
```

Затем `--allow` (или `-a`) в EAL с корректным BDF.

---

### `Requested device 0000:xx:yy.z cannot be used` (но процесс продолжает)

**Причина.** DPDK probe споткнулся на PCI устройстве которое не нужно (чужая NIC / virtio). На dev VM это норма — видим `VIRTIO_INIT` warning.

**Fix.** Ignore если pktgate всё равно запустился. Для prod — указать explicit `-a <BDF>` whitelist, чтобы DPDK не ходил по всем PCI устройствам.

---

### `tailq panic` / `PANIC in rte_eal_init()` с дубликатами registration

**Причина.** Dual DPDK install (source build + distro package) → PMD грузятся дважды, tailq registration conflict (см. `docs/install.md` §Dual-install caveat).

**Диагностика.**

```bash
ldd /usr/local/bin/pktgate_dpdk | grep dpdk
# Сверить с тем что даёт pkg-config:
pkg-config libdpdk --libs-only-L
```

**Fix.**

```bash
export PKTGATE_DPDK_DRIVER_DIR=/path/to/build/drivers
# или в systemd unit'е:
# Environment=PKTGATE_DPDK_DRIVER_DIR=/opt/dpdk-25.11/build/drivers
```

---

### `JSON syntax error` / `unknown top-level field` / другие parse errors

**Причина.** Ошибка в `config.json` — строгий whitelist валит первый неизвестный ключ.

**Диагностика.** Пустите бинарь с `--exit-after-init` — он пройдёт parse + validate + compile без траффика:

```bash
sudo pktgate_dpdk --config /etc/pktgate/config.json \
    --exit-after-init -l 0,1 -n 4 --file-prefix=dry-run
# stderr покажет ParseError::Kind и имя поля
```

Полный список error kind'ов — `docs/configuration.md` §Parse errors.

---

### `kUnresolvedInterfaceRef` / `kUnresolvedObject` / `kUnresolvedTargetPort`

**Причина.** Rule ссылается на interface / object / target_port, которого нет в секции `interface_roles` / `objects.subnets`.

**Fix.** Прочитать сообщение — там rule_id и имя отсутствующей ссылки. Проверить опечатки.

---

### `kSizingBelowMin`

**Причина.** `sizing.rules_per_layer_max < 16` (D6 hard minimum).

**Fix.** Поднять до ≥16. Если действительно хотите микро-конфиг — `kSizingDevDefaults` (256) без секции `sizing` в config.

---

## Boot stage — процесс стартует но не готов

### `{"ready":true}` никогда не появляется

**Диагностика.**

```bash
journalctl -u pktgate -o cat -n 50 | jq .
# Смотрим последний event перед зависанием.
```

| Последний event | Вероятная причина |
|---|---|
| `eal_init_ok` | port probe застрял — bad vfio binding / PCI fault |
| `ports_started` | ruleset compile залип (очень большие hash tables при sizing prod) |
| `port_resolved` | role resolution fails — имя порта ≠ DPDK-probed name |
| `prom_endpoint_ready` | inotify setup fails — `/etc/pktgate` не существует или нет read permission |

---

### `prom_endpoint_ready` показан, но `curl 127.0.0.1:9090/metrics` connection refused

**Причина.** Port занят другим процессом, pktgate failover'нулся тихо.

**Диагностика.**

```bash
ss -tlnp | grep 9090
sudo lsof -iTCP:9090 -sTCP:LISTEN
```

**Fix.** Сменить `sizing.prom_port` или убить conflict'ующий процесс. Также `0` в `prom_port` даёт OS-assigned port — event `prom_endpoint_ready` покажет реально выделенный.

---

## Dataplane — траффик не идёт

### `port_rx_packets_total == 0` у всех портов

**Причина.** Пакеты не доходят до PMD'а.

**Диагностика.**

```bash
# На peer стороне проверить отправку:
sudo tcpdump -i <peer-iface> -c 10 -nn

# Для TAP:
sudo ip link show dtap0
# flags должны включать UP,LOWER_UP

# Для vhost:
ls -la /run/pktgate/vhost.sock
# Socket должен существовать + peer (QEMU/testpmd) подключён
```

**Fix**.
- TAP: `sudo ip link set dtap0 up` на хосте; если NetworkManager пытается DHCP'ить TAP — пометить имя как unmanaged через keyfile в `/etc/NetworkManager/conf.d/`:
  ```
  [keyfile]
  unmanaged-devices=interface-name:dtap*
  ```
  + `sudo systemctl reload NetworkManager`.
- vhost: проверить что peer стартанул и коннект к socket'у (testpmd / QEMU логи).
- PCI: link up? cable? SFP?

---

### `port_rx_packets_total > 0` но `port_tx_packets_total == 0`

**Причина.** Пакеты RX'ятся но не форвардятся.

**Диагностика.**

```bash
# Default behavior drop и нет match'ей — всё падает:
curl -s http://127.0.0.1:9090/metrics | grep pktgate_default_action_total
# Если быстро растёт — rules не цепляются на этот трафик.
```

**Fix.** Проверить rule set:
- `dst_port` / `dst_subnet` / `ethertype` соответствуют реально приходящим пакетам?
- `next_layer` правильный (L2 rule с `next_layer:l3` необходимо для попадания в L3/L4)?
- Помни: **L2 action: allow — НЕ terminal если указан next_layer**, передача в L3 происходит только при явном `next_layer:l3`.

Детальный debug:

```bash
# Запустить с низким pkt_rate и собрать per-rule counters:
curl -s http://127.0.0.1:9090/metrics | grep pktgate_rule_packets_total
# Видно что zero counters → ни одного match'а, rules не покрывают трафик.
```

---

### `port_rx_dropped_total` растёт

**Причина.** Mempool exhausted, или RX ring переполняется (lcore не справляется).

**Диагностика.**

```bash
curl -s http://127.0.0.1:9090/metrics | grep -E 'mempool_(in_use|free)|cycles_per_burst'
```

**Fix.**

| Симптом | Мера |
|---|---|
| `mempool_in_use` растёт к пределу | Увеличить `PKTGATE_TEST_MBUF_POOL_SIZE` env или default size в коде |
| `cycles_per_burst p99 > 500µs` | Worker overloaded — больше lcore'ов через `--workers N` |
| Idle ratio низкий, cycles low | RX ring config underprovisioned, нужен DPDK tuning |

---

### `tx_burst_short_total` растёт (D43 back-pressure)

**Причина.** TX peer (downstream NIC / vhost peer / mirror sink) не поспевает за line rate.

**Диагностика.**

```bash
curl -s http://127.0.0.1:9090/metrics | grep -E 'tx_(dropped|burst_short)'
```

**Fix.**
- Downstream peer: увеличить queue depth, проверить CPU / interrupt affinity.
- Mirror sink: снизить mirror rate (rule с более специфичным match) или выделить peer'у больше ресурсов.
- Если это prod NIC с `autoneg` проблемой — принудительно `ethtool -s <iface> speed 10000 duplex full autoneg off`.

---

### `mirror_dropped_total` растёт

**Причина.** Mirror slow consumer — pktgate M16 back-pressure threshold (1k accumulated ticks) сработал, дропаем **клоны** (оригинал форвардится всегда).

**Fix.** Это design intent — origin traffic защищён. Если хотите все копии — поднимите mirror peer'у capacity. Если mirror для компliance (и mustn't be lossy) — pre-filter на L4 чтобы mirror'ить только узкую часть трафика.

---

### `dispatch_unreachable_total > 0`

**🚨 Software bug. Never normal.** D25 инвариант: `apply_action` имеет default arm + `-Wswitch-enum` на компиляции, чтобы unreachable branch не существовал на hot path'е. Если счётчик бампнулся — значит, binary corruption или undefined behavior.

**Fix.** Capture `stats_on_exit` JSON из stdout, сопоставить с `rule_id` → escalate. Не расчитывать на self-recovery; рестартовать процесс — по `systemctl restart pktgate`.

---

## Control plane — reload не работает

### inotify не триггерит reload

**Причина.** Редактор пишет не в тот файл (через temp + rename); kernel inotify_add_watch умер; путь symlink'ом.

**Диагностика.**

```bash
sudo lsof -p $(pgrep -u root pktgate_dpdk) | grep inotify
# Должен быть inotify fd

# Проверить что pktgate watch'ит нужный dir:
journalctl -u pktgate -o cat | grep inotify_watch_ready
# Event включает "dir" и "basename"
```

**Fix.**
- Редактировать **через atomic replace**: `install -m 0644 /tmp/new.json /etc/pktgate/config.json`.
- Не редактировать symlink — pktgate watch'ит `realpath(config.json)`.
- Проверить что `sudo systemctl restart pktgate` после любого изменения `--config` path'а.

---

### reload с UDS cmd_socket возвращает `err bad_verb`

**Причина.** Протокол — `reload <json>\n` с **одной** строкой payload'а; многострочный JSON будет обрезан на первой `\n`.

**Fix.**

```bash
# Правильно — JSON одной строкой:
payload=$(jq -c . /etc/pktgate/config.json)
echo "reload $payload" | sudo socat - UNIX-CONNECT:/run/pktgate/cmd.sock
```

---

### reload возвращает `err <kind>:<message>` (live traffic продолжается)

**Норма.** Bad-config reject'ится atomic, до publish'а. Живая генерация не теряется.

**Диагностика.**

```bash
curl -s http://127.0.0.1:9090/metrics | grep 'pktgate_reload_total{result='
# result!="success" → growing counter
```

`kind` из error строки даст `parse_error` / `validate_error` / `compile_error` /
`build_eal_error` / `timeout` / `internal_error`. Fix — исправить config и
повторить reload.

---

### `reload_timeout_total` растёт

**Причина.** QSBR synchronize не уложился в deadline (500ms default) —
worker lcore застрял или PMD hang'ается.

**Диагностика.**

```bash
# pending_free_depth > 0 sustained → старые ruleset'ы копятся:
curl -s http://127.0.0.1:9090/metrics | grep reload_pending_free_depth

# Worker живой?
curl -s http://127.0.0.1:9090/metrics | grep pktgate_lcore_packets_total
# Если какой-то lcore застыл (counter не растёт) → он виновник
```

**Fix.**
- Hang'нутый worker — рестарт процесса (нет in-build watchdog'а, M12 deferred).
- Systematic timeout'ы — проверить CPU pinning (может scheduler перебрасывает worker'а), `isolcpus` в grub.

---

## Shutdown — процесс не exit'ится

### `systemctl stop pktgate` висит 30s

**Причина.** Workers не дрейнят → `TimeoutStopSec` истекает → systemd шлёт SIGKILL.

**Диагностика.**

```bash
# Последние events перед kill'ом:
journalctl -u pktgate -o cat -n 30 | tail -20
```

`{"event":"eal_cleanup"}` эмиттится всегда — даже при vhost-профиле, когда сам `rte_eal_cleanup()` пропускается (см. `docs/operations.md` §Vhost caveat). Если виден `workers_exit` но не `eal_cleanup` — worker lcore застрял в cleanup path ещё до eal-стадии.

Если `workers_exit` **не** появляется — worker lcore застрял на PMD. Поднимаем `strace -p <pid>` на worker thread'ах.

**Fix.** Если vhost caveat — `TimeoutStopSec=10s` достаточно. Если hang — перезагрузка NIC/хоста; проверить драйвер / firmware.

---

### После SIGKILL не стартует заново: `Cannot init memory`

**Причина.** Stale `/run/dpdk/<file-prefix>/` от убитого процесса — shared memory mapping'и не освобождены.

**Fix.**

```bash
sudo sh -c 'rm -rf /run/dpdk/pktgate*'
```

На системах с отдельным `/var/run` (не symlink на `/run`) — то же под
`/var/run/dpdk/`. На современной Fedora / Debian / Ubuntu `/var/run` —
symlink, достаточно одной команды под `/run/dpdk/`.

Затем `systemctl start pktgate`.

---

### Vhost socket leak

**Причина.** TAP vdev освобождается автоматически (ядерный netlink), но **vhost-user socket на disk'е может остаться** при SIGKILL.

**Fix.**

```bash
sudo rm -f /run/pktgate/vhost*.sock
```

На graceful SIGTERM pktgate пишет `{"event":"vhost_socket_cleaned"}` перед exit'ом.

---

## Общие диагностические команды

```bash
# Полный snapshot counters:
curl -s http://127.0.0.1:9090/metrics | grep ^pktgate_ > /tmp/pktgate-snap.txt

# Следить за изменениями counters:
watch -n 1 "curl -s http://127.0.0.1:9090/metrics | grep pktgate_rule_packets"

# Full event log:
journalctl -u pktgate -o cat -f | jq .

# DPDK telemetry — порты, queue stats, mempool stats:
/usr/local/bin/dpdk-telemetry.py --file-prefix pktgate
# В интерактивном режиме:
#   /                       — список команд
#   /ethdev/list            — порты
#   /ethdev/stats,0         — stats порта 0
#   /mempool/info,pktgate_mbuf_pool
#   /pktgate/reload,<json>  — наш кастомный reload endpoint

# Hot path syscall trace (если процесс завис):
sudo strace -f -p $(pgrep -u root pktgate_dpdk) 2>&1 | head -100
```

## Где искать подробности

- Parse error kind table → `docs/configuration.md` §Parse errors
- Reload channels + counters → `docs/operations.md` §Hot reload
- Counter catalog с семантикой → `docs/observability.md`
- Known limitations + caveats → `docs/limitations.md`
- Для разработчиков: `review-notes.md` §P/D items, `implementation-plan-errata.md`
