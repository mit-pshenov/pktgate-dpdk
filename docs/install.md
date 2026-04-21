# Установка

## Системные требования

| | Dev VM | Production |
|---|---|---|
| OS | Fedora 43 / RHEL 9 / Ubuntu 22.04+ с DPDK 25.11 | то же |
| Kernel | ≥ 5.4 | ≥ 5.4, рекомендуется LTS ≥ 5.15 |
| glibc | ≥ 2.34 | ≥ 2.34 |
| Toolchain | GCC ≥ 14 **или** Clang ≥ 18 (C++20) | то же |
| DPDK | 25.11 (source build или дистрибутивный пакет) | 25.11 |
| Hugepages | 512 × 2 МБ (≈ 1 ГБ) | 4+ ГБ × 2 МБ или 8 × 1 ГБ |
| NUMA | single-node (VM) | multi-socket; hugepages + mempool на том же узле что NIC |
| root | нужен (EAL init, VFIO, hugepages) | нужен (или CAP_IPC_LOCK + CAP_NET_ADMIN + CAP_SYS_RAWIO) |

Hugepages:

```bash
# runtime, временно
echo 512 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p /dev/hugepages
mountpoint -q /dev/hugepages || sudo mount -t hugetlbfs -o pagesize=2M none /dev/hugepages

# persistent — через /etc/default/grub + reboot
# GRUB_CMDLINE_LINUX="... default_hugepagesz=1G hugepagesz=1G hugepages=8"
```

Dev VM идемпотентный bring-up: `scripts/dev_hugepages.sh`.

## Supported NICs

**Architectural targets** (D4 — rule tiering и hw_offload_hint hook
готовы, deploy не бенчили на этой платформе):

- Intel E810 (`ice` driver)
- Intel XL710 (`i40e` driver)
- Mellanox ConnectX-5 / ConnectX-6 (`mlx5` driver)

**Validated deploy profiles** (Phase 2, функциональное покрытие):

- **TAP** (`net_tap` vdev) — CI / dev baseline. Интерфейс на ядре,
  нет back-pressure на TX.
- **vhost-user** (`net_vhost` vdev) — production zero-copy shared-memory
  profile (пара с QEMU / testpmd peer). DPDK 25.11 net_vhost имеет
  известный teardown race — pktgate пропускает `rte_eal_cleanup()`
  при наличии vhost-роли (см. `docs/operations.md` §Graceful shutdown).

PCI prod NIC на dev-среде проекта недоступен — рекомендуется
валидировать отдельно на целевой платформе перед production rollout.

## Сборка из исходников

```bash
git clone <repo> pktgate-dpdk
cd pktgate-dpdk

# Production build (aka dev-release) — `-O3 -march=native -DNDEBUG`.
cmake --preset dev-release
cmake --build build/dev-release -j

# Binary:
ls -la build/dev-release/pktgate
```

CMake presets (`CMakePresets.json`):

| Preset | Compiler | Use case |
|---|---|---|
| `dev-debug` | GCC, `-O0 -g3` | Fast iteration, no sanitizers |
| `dev-release` | GCC, `-O3 -march=native` | Prod build |
| `dev-asan` | Clang, ASan+UBSan | QA memory safety |
| `dev-ubsan` | Clang, UBSan only | QA alignment / UB |
| `dev-tsan` | Clang, TSan | QA data races |

Для production отгружайте `dev-release`. Остальные пресеты — QA-only.

## DPDK discovery

Проект находит DPDK через `pkg-config libdpdk` (см. `CMakeLists.txt`
`pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)`). На dev VM
используется meson-uninstalled `.pc`-файл:

```bash
export PKG_CONFIG_PATH=/path/to/dpdk-25.11/build/meson-uninstalled
```

На production host'е обычно достаточно установить дистрибутивный
пакет `dpdk-devel` / `libdpdk-dev` — `pkg-config` находит `libdpdk`
автоматически.

### Dual-install caveat

Если в системе одновременно присутствуют две установки DPDK (например,
source build в `~/Dev/dpdk-25.11` **и** `/usr/local/lib/dpdk/pmds-25/`),
автоматическая загрузка PMD из второй приводит к tailq panic на
`rte_eal_init`. pktgate не передаёт `-d <pmd-dir>` в EAL по умолчанию;
тесты и production должны явно указать driver path через env var:

```bash
export PKTGATE_DPDK_DRIVER_DIR=/path/to/dpdk-25.11/build/drivers
```

Если DPDK установлен только из дистрибутивных пакетов — переменную
задавать не нужно, PMD найдутся по дефолтным путям `pkg-config`.

## NIC bind

Production путь — VFIO:

```bash
sudo modprobe vfio-pci
sudo dpdk-devbind.py -b vfio-pci 0000:xx:yy.z
sudo dpdk-devbind.py --status
```

TAP / vhost deploy profile'ы bind'а не требуют — vdev создаётся
параметрами EAL (`--vdev=net_tap0,iface=dtap0` /
`--vdev=net_vhost0,iface=/run/pktgate/vhost.sock,queues=1`).

## Install paths

**Рекомендуемая layout для production:**

```
/usr/local/bin/pktgate              # бинарь (скопировать из build/dev-release/)
/etc/pktgate/config.json            # главный config
/run/pktgate/cmd.sock               # UDS cmd socket (если используется)
/var/log/pktgate/                   # журнал (если не через journald)
```

Systemd unit и примерный layout — в `docs/operations.md`. В
репозитории лежит `systemd/pktgate-devvm.service` — это **dev-only
test matrix runner**, не production unit.
