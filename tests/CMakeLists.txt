# tests/CMakeLists.txt
#
# Test-tree root. Real helpers (pktgate_add_test, label taxonomy,
# sanitizer compatibility lists) land in M0 C3. For now we just pull in
# GTest and hand off to the smoke subdir.

find_package(GTest REQUIRED)

add_subdirectory(smoke)
add_subdirectory(unit)
add_subdirectory(placeholders)
add_subdirectory(functional)
add_subdirectory(integration)
# M11 C3 — chaos tier (X1.1 inotify reload storm; concurrency sentinel
# for the inotify watcher thread + debounce + reload funnel under TSAN).
add_subdirectory(chaos)
