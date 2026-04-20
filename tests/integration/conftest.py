# tests/integration/conftest.py
#
# M15 C3 — integration-tier Python conftest.
#
# The integration tier was pure C++ (gtest + EAL) through M14. M15 C3
# adds the first Python pytest entry — `test_m15_vhost_pair.py` — which
# needs the session-scoped `nm_unmanaged_tap` fixture so NetworkManager
# leaves the `dtap_m15_ing` tap alone.
#
# pytest does NOT auto-walk sibling directories' conftest.py files, so
# we import the functional conftest as a uniquely-named module and
# re-export the fixture (same pattern as tests/chaos/conftest.py). We
# can't just `from conftest import ...` because this file is itself
# `conftest` → circular import risk.

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

# Re-export the session-scoped NM keyfile fixture — the integration
# test uses it via `pytestmark = pytest.mark.usefixtures("nm_unmanaged_tap")`.
nm_unmanaged_tap = _mod.nm_unmanaged_tap
