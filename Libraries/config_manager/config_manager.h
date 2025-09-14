#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------- Structures that mirror your JSON ----------
//
// JSON shape:
//
// {
//   "stream_filters": [ { stream_id, match{...}, gate_id, meter_id }, ... ],
//   "stream_gates":   [ { gate_id, gate_enable, drop_when_close, cycle_time_ns, gate_open_ns, gate_close_ns }, ... ],
//   "flow_meters":    [ { meter_id, enable, rate_bps, burst_bytes }, ... ]
// }

typedef struct {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t vlan_id;   // 0..4095
    uint8_t  pcp;       // 0..7
} config_stream_match_t;

typedef struct {
    uint32_t              stream_id;  // unique stream identifier in config
    config_stream_match_t match;      // {dest_mac, src_mac, vlan_id, pcp}
    uint32_t              gate_id;    // reference into stream_gates
    uint32_t              meter_id;   // reference into flow_meters
} config_stream_filter_t;

typedef struct {
    uint32_t gate_id;           // key
    bool     gate_enable;       // if false OR cycle_time_ns==0 => gate ignored (always open)
    bool     drop_when_closed;  // drop when gate closed (JSON uses "drop_when_close" -> parser maps to this)
    uint64_t cycle_time_ns;     // ns
    uint64_t gate_open_ns;      // ns offset in cycle
    uint64_t gate_close_ns;     // ns offset in cycle (non-wrapping model expected by your code)
} config_stream_gate_t;

typedef struct {
    uint32_t meter_id;     // key
    bool     enable;       // policer enable
    uint64_t rate_bps;     // bytes per second (JSON field name: "rate_bps")
    uint64_t burst_bytes;  // bucket capacity in bytes (JSON field name: "burst_bytes")
} config_flow_meter_t;

typedef struct {
    config_stream_filter_t* stream_filters;
    uint32_t                stream_filters_count;

    config_stream_gate_t*   stream_gates;
    uint32_t                stream_gates_count;

    config_flow_meter_t*    flow_meters;
    uint32_t                flow_meters_count;
} config_data_t;

// ---------- API ----------

/**
 * @brief Load configuration from JSON file into config_data_t.
 *        Arrays are heap-allocated; call config_manager_cleanup() to free.
 * @param path   Path to JSON (e.g., "ConfigFile/config.json")
 * @param out    Output config object (must be non-NULL).
 * @return true on success, false on error.
 */
bool config_manager_load(const char* path, config_data_t* out);

/**
 * @brief Free memory allocated inside config_data_t by config_manager_load().
 */
void config_manager_cleanup(config_data_t* config);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_MANAGER_H
