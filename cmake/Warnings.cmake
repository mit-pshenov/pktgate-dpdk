# cmake/Warnings.cmake — warning wall for pktgate-dpdk
#
# Single function pktgate_apply_warnings(<target>) that attaches the
# project-wide warning set to <target> as PRIVATE compile options.
# Preset-level CXX flags don't touch warnings — only our own targets
# get -Werror, so GTest/DPDK headers are free to be sloppy.
#
# The set is pulled from harness.md §H2.10 (ci-gcc) which in turn
# references design.md §13 and D25 (-Wswitch-enum is load-bearing for
# apply_action's default arms).

function(pktgate_apply_warnings tgt)
  set(_warn_common
    -Wall -Wextra -Wpedantic -Werror
    -Wswitch-enum                # D21 / D25 — hard stop on verdict enum drift
    -Wshadow
    -Wconversion -Wsign-conversion
    -Wnon-virtual-dtor
    -Wundef
    -Wcast-align
    -Wuninitialized
    -Wnull-dereference
    -Wformat=2
    -Wmissing-declarations
    -Wstrict-aliasing=2          # L1 from the 4th review, landed in build flags
    -fstrict-aliasing -fno-common
  )
  target_compile_options(${tgt} PRIVATE ${_warn_common})
endfunction()
