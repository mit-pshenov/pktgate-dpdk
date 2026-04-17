// src/ctl/telemetry_reload.cpp
//
// M8 C5 — /pktgate/reload telemetry command handler.
//
// See telemetry_reload.h for scope. The callback validates the
// `params` argument (must be a JSON object — the caller's config
// document verbatim) and forwards it to `ctl::reload::deploy()`.
// The result is rendered into the rte_tel_data dict per design
// §12.3 (stats-on-exit schema mirrors this field set).
//
// D30 precedent: the DPDK 25.11 telemetry ABI is
//   typedef int (*telemetry_cb)(const char *cmd,
//                               const char *params,
//                               struct rte_tel_data *info);
//   int rte_telemetry_register_cmd(const char *cmd,
//                                  telemetry_cb fn,
//                                  const char *help);
// Verified against /home/mit/Dev/dpdk-25.11/lib/telemetry/rte_telemetry.h
// before coding. Don't take hearsay from reviewers without re-checking.

#include "src/ctl/telemetry_reload.h"

#include <cstring>
#include <string>
#include <string_view>

#include <rte_telemetry.h>

#include "src/ctl/reload.h"

namespace pktgate::ctl::telemetry_reload {

namespace {

// Map DeployError onto the short string literals used both in the
// cmd_socket reply and in the /pktgate/reload dict. Keep in sync with
// main.cpp's stats_on_exit emitter and tests/integration/test_reload.cpp.
const char* deploy_error_name(reload::DeployError e) {
  switch (e) {
    case reload::DeployError::kOk:              return "ok";
    case reload::DeployError::kParse:           return "parse";
    case reload::DeployError::kValidate:        return "validate";
    case reload::DeployError::kValidatorBudget: return "validator_budget";
    case reload::DeployError::kCompile:         return "compile";
    case reload::DeployError::kBuildEal:        return "build_eal";
    case reload::DeployError::kReloadTimeout:   return "reload_timeout";
    case reload::DeployError::kInternal:        return "internal";
  }
  return "unknown";
}

// Single entry point — the telemetry callback.
//
// `params` is the config JSON (may be empty / null if the caller
// forgot — treat as parse error downstream). Telemetry returns
// `length of buffer used on success`; we only speak through
// rte_tel_data and return 0 on success, negative on hard error
// (malformed invocation). A FUNCTIONAL reload failure (parse,
// validate, etc.) is still a success return — the error is
// reported in the result dict.
int telemetry_reload_cb(const char* /*cmd*/,
                        const char* params,
                        struct rte_tel_data* info) {
  if (info == nullptr) return -EINVAL;
  rte_tel_data_start_dict(info);

  if (params == nullptr || params[0] == '\0') {
    rte_tel_data_add_dict_int(info, "ok", 0);
    rte_tel_data_add_dict_string(info, "error",
                                 "telemetry_reload: empty params");
    rte_tel_data_add_dict_string(info, "kind", "parse");
    return 0;
  }

  reload::DeployResult r = reload::deploy(std::string_view{params});

  rte_tel_data_add_dict_int(info, "ok", r.ok ? 1 : 0);
  rte_tel_data_add_dict_string(info, "kind", deploy_error_name(r.kind));
  rte_tel_data_add_dict_uint(info, "generation",
                             static_cast<std::uint64_t>(r.generation));
  if (!r.ok) {
    rte_tel_data_add_dict_string(info, "error", r.error.c_str());
  }
  return 0;
}

}  // namespace

int register_endpoint() {
  return rte_telemetry_register_cmd(
      "/pktgate/reload", telemetry_reload_cb,
      "Reload active ruleset from JSON passed as params. "
      "Returns {ok, kind, generation, error?}.");
}

}  // namespace pktgate::ctl::telemetry_reload
