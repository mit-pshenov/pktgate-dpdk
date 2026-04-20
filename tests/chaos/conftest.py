# tests/chaos/conftest.py
#
# M11 C3 — chaos-tier conftest.
#
# Chaos tests reuse the functional-tier PktgateProcess fixture
# wholesale. pytest does not walk sibling directories' conftest.py
# files, so we import the functional conftest as a uniquely-named
# module and re-export its fixtures. We can't just
# `from conftest import ...` because our own file is also named
# `conftest` → circular import.

import importlib.util
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_FUNCTIONAL_CONFTEST = os.path.normpath(
    os.path.join(_HERE, "..", "functional", "conftest.py")
)

_spec = importlib.util.spec_from_file_location(
    "pktgate_functional_conftest", _FUNCTIONAL_CONFTEST,
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

# Re-export the pytest fixture so chaos tests can request it by name.
pktgate_process = _mod.pktgate_process
# M16 C4 — chaos.test_m16_mirror_* need the session-scoped NM keyfile
# fixture too; re-export it the same way pktgate_process is re-exported.
# Without this the chaos tests see "fixture 'nm_unmanaged_tap' not found".
nm_unmanaged_tap = _mod.nm_unmanaged_tap
