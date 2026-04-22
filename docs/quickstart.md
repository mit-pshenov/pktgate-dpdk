# Quickstart

Минимальная работающая инсталляция — от пустого хоста до первого
успешного scrape `/metrics`. Оценочно 10 минут при готовых hugepages.

## Prereq checklist

- [ ] Hugepages смонтированы (≥ 512 × 2 МБ) — `cat /proc/meminfo | grep Huge`
- [ ] Нужные NIC bound к vfio-pci **или** используется TAP / vhost vdev
- [ ] DPDK 25.11 обнаруживается `pkg-config libdpdk --modversion`
- [ ] Бинарь собран: `build/dev-release/pktgate_dpdk`
- [ ] Запуск под root (или с нужными capabilities)

Детали по каждому пункту — `docs/install.md`.

## Минимальный config

Для quickstart'а используем TAP profile — никаких PCI bind'ов,
любой Linux host'ит. Положить в `/etc/pktgate/config.json`:

```json
{
  "version": 1,
  "interface_roles": {
    "upstream_port":   {"vdev": "net_tap0,iface=dtap_qs_up"},
    "downstream_port": {"vdev": "net_tap1,iface=dtap_qs_down"}
  },
  "default_behavior": "drop",
  "pipeline": {
    "layer_2": [],
    "layer_3": [],
    "layer_4": [
      {
        "id": 1001,
        "proto": 6,
        "dst_port": 443,
        "action": {"type": "allow"}
      }
    ]
  },
  "sizing": {
    "rules_per_layer_max":   256,
    "mac_entries_max":       256,
    "ipv4_prefixes_max":     1024,
    "ipv6_prefixes_max":     1024,
    "l4_entries_max":        256,
    "vrf_entries_max":       32,
    "rate_limit_rules_max":  256,
    "ethertype_entries_max": 32,
    "vlan_entries_max":      256,
    "pcp_entries_max":       8,
    "prom_port":             9090
  }
}
```

Одно ALLOW-правило на TCP/443, всё остальное падает в `default_behavior:
drop`. Две TAP vdev в роли upstream/downstream — `dpdk-devbind.py` не
нужен.

## Запуск

```bash
sudo build/dev-release/pktgate_dpdk \
    --config /etc/pktgate/config.json \
    -l 0,1 \
    -n 4 \
    --vdev=net_tap0,iface=dtap_qs_up \
    --vdev=net_tap1,iface=dtap_qs_down \
    --file-prefix=pktgate_qs
```

(Путь `/usr/local/bin/pktgate_dpdk` — для установленного бинаря;
install-шаги и systemd-layout — в `docs/operations.md`.)

`pktgate_dpdk` забирает свои флаги (`--config`, опционально
`--workers <N>`, `--mbuf-size <bytes>`, `--ctl-sock <path>`,
`--exit-after-init` для smoke check) из argv, остальное уходит в EAL
(`-l`, `-n`, `--vdev`, `--file-prefix`, `-a / --allow` для whitelist
PCI и т.д.). Разделитель `--` не нужен — pktgate просто скипает
свои флаги и отдаёт остаток EAL'у.

**Замечание:** `--vdev` при vhost / TAP нужно указывать **и** в EAL
args (чтобы DPDK probe'нул vdev), **и** в `interface_roles` конфига
(чтобы pktgate разрешил role → port_id). Имя в `interface_roles.vdev`
должно совпадать с тем, что приходит к EAL, с точностью до arg'ов.

## Verify

После запуска на stdout появятся JSON-event'ы (`eal_init_ok`,
`ports_started`, `ruleset_published`, `port_resolved`,
`worker_ports`, `prom_endpoint_ready`). Критичные:

```
{"event":"prom_endpoint_ready","port":9090}
{"event":"worker_ports","port_id":0,"tx_port_id":1}
```

Scrape `/metrics` в другом терминале:

```bash
curl -s http://127.0.0.1:9090/metrics | grep ^pktgate_ | head
```

Должны появиться базовые счётчики — `pktgate_port_rx_packets_total`,
`pktgate_port_tx_packets_total`, `pktgate_active_rules`,
`pktgate_active_generation`, `pktgate_publisher_generation`.
Полный справочник — `docs/observability.md`.

## Smoke — send a packet

TAP-интерфейсы на уровне ядра — можно kick'нуть пакет через обычный
`ping` / `socat` / `scapy`:

```bash
# На хосте (другой терминал), пока pktgate работает:
sudo ip link set dtap_qs_up up
sudo ip addr add 10.99.0.1/24 dev dtap_qs_up

# Отправить TCP SYN на 443 — правило id=1001 должно разрешить:
sudo hping3 -S -p 443 -c 1 10.99.0.99 -I dtap_qs_up
```

Счётчик `pktgate_port_rx_packets_total{port="0"}` инкрементнётся;
`pktgate_rule_packets_total{rule_id="1001"}` тоже, если matcher
зацепил.

## Остановить

```bash
sudo pkill -TERM pktgate
# Или: systemctl stop pktgate.service (если унит установлен — см. operations.md)
```

SIGTERM → graceful drain → exit. TAP-интерфейсы исчезают вместе с
процессом; vhost UDS чистится автоматически (`vhost_socket_cleaned`
event на stdout перед exit'ом).

Hot reload (inotify / UDS / DPDK telemetry), systemd unit, `--ctl-sock`
аргумент — out of scope для quickstart'а; см. `docs/operations.md`.
