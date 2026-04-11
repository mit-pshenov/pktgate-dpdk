# tests/placeholders/CMakeLists.txt
#
# Label scaffolding. These tests do nothing except keep a scope label
# reachable until a real test with that label lands. The ctest
# label-reachability guard (smoke.label_reachability) requires at
# least one test per scope label, so these exist to satisfy it on M0.
#
# Lifecycle — each placeholder dies at a specific milestone:
#
#   placeholder.unit      -> DELETED in M1 C1 (real U1.1/U1.2/U1.3 cover
#                            the `unit` label via tests/unit/test_parser.cpp)
#   placeholder.corner    -> deleted when M4 lands the first C1.* case
#   placeholder.reload    -> deleted when M8 lands the first reload test
#   placeholder.security  -> deleted when M11 lands D38 auth tests
#   placeholder.sentinel  -> deleted when M5/M6 lands the first of the
#                            six sentinels (test-plan.md §5)
#
# When deleting one, also grep `scripts/check-ctest-labels.sh` to make
# sure the label is still required (it should be — required set is a
# contract, not a placeholder-driven list).

pktgate_add_placeholder_test(NAME placeholder.corner   LABELS corner)
pktgate_add_placeholder_test(NAME placeholder.reload   LABELS reload)
pktgate_add_placeholder_test(NAME placeholder.security LABELS security)
pktgate_add_placeholder_test(NAME placeholder.sentinel LABELS sentinel)
