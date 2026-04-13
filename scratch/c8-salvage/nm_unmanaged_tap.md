# F2.3 root cause — NetworkManager DHCP on dtap interfaces

## Symptom

F2.3 (and adjacent F2 tests) flake in the **full suite run** but
pass in **isolation**. The failure mode is not a crash — per-rule
counter assertions fail because the `stats_on_exit` JSON carries
unexpected `matched_packets` increments on rules that should not
have seen any traffic (specifically: a pass-through rule for
ethertype 0x0800 IPv4 fires when the test only injected a VLAN
frame targeted at a different rule).

## Root cause

`dtap_f2_rx` / `dtap_f2_tx` are kernel tap interfaces created by
the DPDK `net_tap` PMD. The moment they appear in the kernel
netdev list, **NetworkManager** notices them and starts managing
them like any other NIC — which includes firing DHCPv4 requests
and IPv6 Router Solicitation. Those frames land in the DPDK RX
ring on `dtap_f2_rx` and go through `classify_l2`, incrementing
whichever rule happens to match (usually an IPv4 or IPv6
ethertype pass).

Between test cases the tap interface is torn down and recreated,
so NM grabs it again, and DHCP fires again. Over a full suite run
this creates a racy trickle of background frames that contaminate
counter assertions non-deterministically.

In isolation a single test finishes before NM gets through its
DHCP timeout, so the contamination does not surface.

## Fix — session-scoped NM keyfile

Write a NetworkManager keyfile that marks the test interface
names as unmanaged **before any F2 test starts**, then reload NM
configuration. The file lives for the entire pytest session and
is removed in teardown.

The fixture is session-scoped (not per-test) because the tap
interfaces come and go between tests, and we need NM to consider
them unmanaged **during the inter-test window** as well, not just
when they exist.

## Fixture code (for `tests/functional/conftest.py`)

```python
_NM_CONF_PATH = "/etc/NetworkManager/conf.d/pktgate_test_unmanaged.conf"
_TAP_IFACES_TO_UNMANAGE = ["dtap_f2_rx", "dtap_f2_tx"]


@pytest.fixture(scope="session", autouse=False)
def nm_unmanaged_tap():
    """Mark DPDK test tap interfaces as NM-unmanaged for the whole session."""
    nm_conf_written = False
    try:
        iface_spec = ",".join(
            f"interface-name:{n}" for n in _TAP_IFACES_TO_UNMANAGE
        )
        with open(_NM_CONF_PATH, "w") as f:
            f.write("[keyfile]\n")
            f.write(f"unmanaged-devices={iface_spec}\n")
        subprocess.run(
            ["nmcli", "general", "reload", "conf"],
            capture_output=True,
        )
        nm_conf_written = True
    except OSError:
        # Not writable (e.g., CI without sudo) — best effort.
        pass

    yield  # run the tests

    if nm_conf_written:
        try:
            os.unlink(_NM_CONF_PATH)
            subprocess.run(
                ["nmcli", "general", "reload", "conf"],
                capture_output=True,
            )
        except OSError:
            pass
```

And in `test_f2_l2.py` module header:

```python
pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")
```

`autouse=False` so tests that do not need it (non-F2 tests in
other modules) do not pay the setup cost.

## Why keyfile, not `nmcli device set`

`nmcli device set <iface> managed no` requires the interface to
**exist** at the time of the call. The tap interfaces only appear
when the DPDK binary starts, so we would have to run the command
after binary startup and before the first packet is injected — a
race against NM's own device-detect loop. The keyfile approach is
declarative: NM consults it every time a new interface appears
and applies unmanaged status before DHCP is initiated.

## Caveats

- The path `/etc/NetworkManager/conf.d/` requires root write
  access. Tests must run under sudo on the dev VM (they already
  do for DPDK EAL). The fixture silently no-ops on `OSError` so
  non-root CI does not crash, but the contamination will then
  surface — there is no workaround for a non-root environment
  short of a separate netns.
- The fixture name is fixed (`dtap_f2_rx`, `dtap_f2_tx`). If the
  fresh worker chooses different iface names, update both the
  fixture list and the `--vdev net_tap0,iface=...` arguments in
  the test's EAL argv construction.
- Teardown path races with pytest session exit: if the test
  suite is killed hard (SIGKILL), the keyfile will linger.
  Manual cleanup: `rm /etc/NetworkManager/conf.d/pktgate_test_unmanaged.conf && nmcli general reload conf`.
