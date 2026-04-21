# pktgate-dpdk

Inline L2/L3 packet filter на DPDK для GGSN-Gi интерфейсов — pre-filter
перед DPI. Таргет: 40 Гбит/с на сайт, ≤500 µs latency overhead, packet
loss <0.01%.

## Статус

Phase 2 complete. Доставлены M1-M11, M13, M14-M16 (deploy profiles TAP
+ vhost-user, mirror). M12 (watchdog / HA) отложен. Валидация на
production-NIC не выполнена (E810 / XL710 / mlx5 архитектурно
поддержаны, но не протестированы на железе — см. `docs/limitations.md`).

## Deploy profiles

- **TAP** (`net_tap` vdev) — CI / dev baseline, validated.
- **vhost-user** (`net_vhost` vdev) — production zero-copy shared-memory
  profile, validated.
- **PCI prod NIC** — Intel E810 (ice), Intel XL710 (i40e), Mellanox
  ConnectX-5 / ConnectX-6 (mlx5) — архитектурные таргеты, не bench'ились.

## Requirements

- DPDK 25.11
- GCC ≥ 14 или Clang ≥ 18 (C++20)
- Linux kernel ≥ 5.4
- Hugepages: ≥512 × 2 МБ (dev), 4+ ГБ × 2 МБ или 8 × 1 ГБ (prod)
- root (для EAL init, VFIO, hugepages)

## Документация

| Файл | Что внутри |
|---|---|
| [docs/install.md](docs/install.md) | Системные требования, supported NICs, сборка, vfio-pci bind |
| [docs/quickstart.md](docs/quickstart.md) | Минимальный работающий конфиг + запуск + verify |
| [docs/configuration.md](docs/configuration.md) | Полный reference JSON-схемы (interface_roles, rules, actions, sizing) |
| [docs/operations.md](docs/operations.md) | systemd, hot reload (inotify / UDS / telemetry), metrics endpoint |
| [docs/observability.md](docs/observability.md) | Справочник counter'ов с семантикой и триггерами внимания |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Симптом → причины → diagnostic команды |
| [docs/limitations.md](docs/limitations.md) | Non-goals, validated profiles, post-MVP scope |

Для разработчиков: `design.md` (архитектура), `review-notes.md`
(design decisions), `implementation-plan.md` (milestone cycles).
