// src/eal/dynfield.cpp
//
// M3 C4 — mbuf dynfield registration.

#include "src/eal/dynfield.h"

#include <rte_mbuf_dyn.h>

namespace pktgate::eal {

namespace {
// Process-wide dynfield offset. Set once by register_dynfield().
int g_dynfield_offset = -1;
}  // namespace

int register_dynfield() {
  static const struct rte_mbuf_dynfield dynfield_desc = {
      .name = "pktgate_dynfield",
      .size = sizeof(PktgateDynfield),
      .align = alignof(PktgateDynfield),
      .flags = 0,
  };

  g_dynfield_offset = rte_mbuf_dynfield_register(&dynfield_desc);
  return g_dynfield_offset;
}

int dynfield_offset() {
  return g_dynfield_offset;
}

}  // namespace pktgate::eal
