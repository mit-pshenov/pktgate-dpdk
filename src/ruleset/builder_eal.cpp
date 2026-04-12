// src/ruleset/builder_eal.cpp
//
// M4 C0 — EAL-aware Ruleset population.
//
// Opens rte_hash for L2/L4 primary lookup, rte_fib (DIR24_8) for
// IPv4 L3 LPM, rte_fib6 (TRIE) for IPv6 L3 LPM, and populates them
// from the CompileResult's l{2,3,4}_compound vectors. See
// builder_eal.h for the entry point contract.
//
// D15 — compound primary + filter_mask:
//   * L2 rte_hash key = primary_key (u64 packed: MAC / VLAN / ethertype / PCP)
//   * L4 rte_hash key = primary_key (u32 packed: proto<<16|dport or proto)
//   * L3 FIB stores L3CompoundEntry packed into the 8-byte next_hop slot
//
// D23 — NUMA awareness: socket_id comes from EalPopulateParams and is
//   passed straight to rte_hash_create / rte_fib_create / rte_fib6_create.
//
// D41 — pipeline smoke: populate_ruleset_eal() is the single entry
//   point the full-boot path (and the U4.2-U4.5 EAL unit tests) go
//   through, so any gap between the compiler's compound vectors and
//   the runtime DPDK tables shows up immediately.

#include "src/ruleset/builder_eal.h"

#include <cstring>
#include <string>

#include <rte_errno.h>
#include <rte_fib.h>
#include <rte_fib6.h>
#include <rte_hash.h>
#include <rte_ip6.h>
#include <rte_jhash.h>

#include "src/compiler/rule_compiler.h"

namespace pktgate::ruleset {

namespace {

// eal_deleter callback — stored on Ruleset so ~Ruleset can free the
// DPDK handles without pulling DPDK headers into ruleset.cpp.
void eal_deleter_impl(Ruleset& rs) {
  if (rs.l2_compound_hash) {
    rte_hash_free(rs.l2_compound_hash);
    rs.l2_compound_hash = nullptr;
  }
  if (rs.l4_compound_hash) {
    rte_hash_free(rs.l4_compound_hash);
    rs.l4_compound_hash = nullptr;
  }
  if (rs.l3_v4_fib) {
    rte_fib_free(rs.l3_v4_fib);
    rs.l3_v4_fib = nullptr;
  }
  if (rs.l3_v6_fib) {
    rte_fib6_free(rs.l3_v6_fib);
    rs.l3_v6_fib = nullptr;
  }
  rs.eal_owned = false;
}

// Pack an L3CompoundEntry into the FIB next_hop slot (8B). The layout
// matches L3CompoundEntry bit-for-bit (see types.h) so the dataplane
// lookup can memcpy-reinterpret the uint64_t back out.
std::uint64_t pack_l3_next_hop(const L3CompoundEntry& entry) {
  std::uint64_t nh = 0;
  static_assert(sizeof(L3CompoundEntry) == 8,
                "L3CompoundEntry must fit FIB next_hop slot");
  std::memcpy(&nh, &entry, sizeof(entry));
  return nh;
}

}  // namespace

EalPopulateResult populate_ruleset_eal(Ruleset& rs,
                                       const compiler::CompileResult& cr,
                                       const EalPopulateParams& params) {
  EalPopulateResult result;

  // Guard: caller must not double-populate. If any handle is already
  // set, that's a programming error — refuse rather than leak.
  if (rs.eal_owned || rs.l2_compound_hash || rs.l4_compound_hash ||
      rs.l3_v4_fib || rs.l3_v6_fib) {
    result.error = "populate_ruleset_eal: Ruleset already has EAL state";
    return result;
  }

  const std::uint32_t cap = params.max_entries;
  const int sock = params.socket_id;

  // ---- L2 compound hash ---------------------------------------------------
  //
  // Primary key is a u64 (MAC packed low 6 bytes or narrow field
  // zero-extended). rte_hash stores a pointer into the L2CompoundEntry
  // arena we allocate below — the arena must outlive the hash.
  {
    const auto& src = cr.l2_compound;
    const auto n = src.size();
    if (n > 0) {
      rs.l2_compound_entries = new L2CompoundEntry[n]();
      rs.l2_compound_count = static_cast<std::uint32_t>(n);

      rte_hash_parameters hp{};
      const std::string name = params.name_prefix + "_l2c";
      hp.name = name.c_str();
      hp.entries = cap;
      hp.key_len = sizeof(std::uint64_t);
      hp.hash_func = rte_jhash;
      hp.hash_func_init_val = 0;
      hp.socket_id = sock;
      hp.extra_flag = 0;

      rs.l2_compound_hash = rte_hash_create(&hp);
      if (!rs.l2_compound_hash) {
        result.error = "rte_hash_create(l2) failed: rte_errno=" +
                       std::to_string(rte_errno);
        eal_deleter_impl(rs);
        delete[] rs.l2_compound_entries;
        rs.l2_compound_entries = nullptr;
        rs.l2_compound_count = 0;
        return result;
      }

      for (std::size_t i = 0; i < n; ++i) {
        rs.l2_compound_entries[i] = src[i].entry;
        std::uint64_t key = src[i].primary_key;
        int ret = rte_hash_add_key_data(rs.l2_compound_hash, &key,
                                        &rs.l2_compound_entries[i]);
        if (ret < 0) {
          // Duplicate primary key is a collision — compiler should have
          // already reported this via L4CompileOutput::collisions (L2
          // collision detection is M5 classify_l2 territory). We surface
          // it as an EAL error here so the test can see the failure.
          result.error = "rte_hash_add_key_data(l2) failed at index " +
                         std::to_string(i) +
                         ": ret=" + std::to_string(ret);
          eal_deleter_impl(rs);
          delete[] rs.l2_compound_entries;
          rs.l2_compound_entries = nullptr;
          rs.l2_compound_count = 0;
          return result;
        }
      }
    }
  }

  // ---- L4 compound hash ---------------------------------------------------
  //
  // Primary key is a u32 (proto<<16|dport or proto).
  {
    const auto& src = cr.l4_compound;
    const auto n = src.size();
    if (n > 0) {
      rs.l4_compound_entries = new L4CompoundEntry[n]();
      rs.l4_compound_count = static_cast<std::uint32_t>(n);

      rte_hash_parameters hp{};
      const std::string name = params.name_prefix + "_l4c";
      hp.name = name.c_str();
      hp.entries = cap;
      hp.key_len = sizeof(std::uint32_t);
      hp.hash_func = rte_jhash;
      hp.hash_func_init_val = 0;
      hp.socket_id = sock;
      hp.extra_flag = 0;

      rs.l4_compound_hash = rte_hash_create(&hp);
      if (!rs.l4_compound_hash) {
        result.error = "rte_hash_create(l4) failed: rte_errno=" +
                       std::to_string(rte_errno);
        eal_deleter_impl(rs);
        delete[] rs.l4_compound_entries;
        rs.l4_compound_entries = nullptr;
        rs.l4_compound_count = 0;
        return result;
      }

      for (std::size_t i = 0; i < n; ++i) {
        rs.l4_compound_entries[i] = src[i].entry;
        std::uint32_t key = src[i].primary_key;
        int ret = rte_hash_add_key_data(rs.l4_compound_hash, &key,
                                        &rs.l4_compound_entries[i]);
        if (ret < 0) {
          result.error = "rte_hash_add_key_data(l4) failed at index " +
                         std::to_string(i) +
                         ": ret=" + std::to_string(ret);
          eal_deleter_impl(rs);
          delete[] rs.l4_compound_entries;
          rs.l4_compound_entries = nullptr;
          rs.l4_compound_count = 0;
          return result;
        }
      }
    }
  }

  // ---- L3 FIB (v4 + v6) ---------------------------------------------------
  //
  // DIR24_8 with 8-byte next_hop for IPv4, TRIE with 8-byte next_hop
  // for IPv6. The next_hop slot holds a packed L3CompoundEntry (8B,
  // static_assert enforced in types.h).
  //
  // We always allocate an L3CompoundEntry arena sized to the full
  // l3_compound vector even though the FIB stores a packed copy, so
  // the Ruleset retains an in-order host-side copy for future telemetry
  // / debug paths. The arena lifetime is tied to the Ruleset.
  {
    const auto& src = cr.l3_compound;
    const auto n = src.size();
    if (n > 0) {
      rs.l3_compound_entries = new L3CompoundEntry[n]();
      rs.l3_compound_count = static_cast<std::uint32_t>(n);
      for (std::size_t i = 0; i < n; ++i) {
        rs.l3_compound_entries[i] = src[i].entry;
      }

      // Open v4 FIB (DIR24_8). Always created even if only v6 rules
      // exist — it's cheap and keeps the handle slot reserved.
      //
      // DIR24_8 layout note: `num_tbl8` is NOT the entry capacity; it's
      // the number of DIR24_8 level-2 expansion pages allocated up
      // front. DPDK's own test suite (app/test/test_fib.c) uses 32768.
      // We pick 256 as a small but valid default for dev/unit tests —
      // enough to hold a few hundred distinct prefixes longer than /24
      // without the allocator rejecting the create as "no more tbl8
      // slots". Production sizing is a Sizing-driven knob for M5+.
      {
        rte_fib_conf conf{};
        conf.type = RTE_FIB_DIR24_8;
        conf.default_nh = 0;
        conf.max_routes = static_cast<int>(cap);
        conf.rib_ext_sz = 0;
        conf.dir24_8.nh_sz = RTE_FIB_DIR24_8_8B;
        conf.dir24_8.num_tbl8 = 256;
        conf.flags = 0;

        const std::string name = params.name_prefix + "_l3v4";
        rs.l3_v4_fib = rte_fib_create(name.c_str(), sock, &conf);
        if (!rs.l3_v4_fib) {
          result.error = "rte_fib_create(l3v4) failed: rte_errno=" +
                         std::to_string(rte_errno);
          eal_deleter_impl(rs);
          delete[] rs.l3_compound_entries;
          rs.l3_compound_entries = nullptr;
          rs.l3_compound_count = 0;
          return result;
        }
      }

      // Open v6 FIB (TRIE). Same num_tbl8 rationale as v4 above.
      {
        rte_fib6_conf conf{};
        conf.type = RTE_FIB6_TRIE;
        conf.default_nh = 0;
        conf.max_routes = static_cast<int>(cap);
        conf.rib_ext_sz = 0;
        conf.trie.nh_sz = RTE_FIB6_TRIE_8B;
        conf.trie.num_tbl8 = 256;

        const std::string name = params.name_prefix + "_l3v6";
        rs.l3_v6_fib = rte_fib6_create(name.c_str(), sock, &conf);
        if (!rs.l3_v6_fib) {
          result.error = "rte_fib6_create(l3v6) failed: rte_errno=" +
                         std::to_string(rte_errno);
          eal_deleter_impl(rs);
          delete[] rs.l3_compound_entries;
          rs.l3_compound_entries = nullptr;
          rs.l3_compound_count = 0;
          return result;
        }
      }

      // Add routes. We walk the compound vector once, dispatching per
      // kind into the v4 or v6 FIB. Duplicate prefixes (two rules
      // competing for the same prefix) overwrite each other — first-
      // match-wins is enforced at classify time, not at populate time.
      for (std::size_t i = 0; i < n; ++i) {
        const auto& r = src[i];
        const std::uint64_t nh = pack_l3_next_hop(rs.l3_compound_entries[i]);

        if (r.primary_kind == compiler::L3PrimaryKind::kIpv4DstPrefix) {
          int ret = rte_fib_add(rs.l3_v4_fib, r.ipv4_prefix, r.prefix_len, nh);
          if (ret < 0) {
            result.error = "rte_fib_add(l3v4) failed at index " +
                           std::to_string(i) +
                           ": ret=" + std::to_string(ret);
            eal_deleter_impl(rs);
            delete[] rs.l3_compound_entries;
            rs.l3_compound_entries = nullptr;
            rs.l3_compound_count = 0;
            return result;
          }
        } else {
          // kIpv6DstPrefix
          rte_ipv6_addr v6{};
          std::memcpy(v6.a, r.ipv6_prefix.data(), 16);
          int ret = rte_fib6_add(rs.l3_v6_fib, &v6, r.prefix_len, nh);
          if (ret < 0) {
            result.error = "rte_fib6_add(l3v6) failed at index " +
                           std::to_string(i) +
                           ": ret=" + std::to_string(ret);
            eal_deleter_impl(rs);
            delete[] rs.l3_compound_entries;
            rs.l3_compound_entries = nullptr;
            rs.l3_compound_count = 0;
            return result;
          }
        }
      }
    }
  }

  // All tables open. Commit ownership to the Ruleset.
  rs.eal_owned = true;
  rs.eal_deleter = &eal_deleter_impl;
  result.ok = true;
  return result;
}

}  // namespace pktgate::ruleset
