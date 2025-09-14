// stream_table.h
#ifndef STREAM_TABLE_H
#define STREAM_TABLE_H

#include <stdbool.h>
#include <stdint.h>

#include "config_manager.h"   // for config_data_t (JSON -> config tables)

// forward declare packet type (no include here!)
struct packet_s;


// ----------------------------
// Stream identifier (exact match)
// ----------------------------
typedef struct {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t vlan_id;  // 0..4095
    uint8_t  pcp;      // 0..7
} stream_id_t;

// ---------------------------------------
// PSFP rule per stream (config + runtime)
// ---------------------------------------
typedef struct {
    // --- Identification ---
    stream_id_t id;

    // --- Time Gate configuration (single non-wrapping window) ---
    // If gate_enabled == false or cycle_time_ns == 0 -> always open.
    bool      gate_enabled;
    bool      drop_when_closed;      // true: drop when closed (PSFP behavior)
    uint64_t  cycle_time_ns;         // period (e.g., 1,000,000 ns = 1 ms)
    uint64_t  gate_open_ns;          // open offset within cycle   [0 .. cycle_time_ns)
    uint64_t  gate_close_ns;   

    
    // --- Filter / Policer configuration ---
    // If rate_bytes_per_s == 0 => unlimited (meter disabled or not configured).
    bool      filter_enabled;        // if false -> drop by default
    uint64_t  rate_bytes_per_s;      // bytes per second (from flow_meters.rate_bps)
    uint64_t  burst_bytes;           // bucket capacity in bytes (from flow_meters.burst_bytes)

    // --- Policer runtime state ---
    uint64_t  tokens_bytes;          // current tokens (bytes)
    uint64_t  last_refresh_ns;       // last refill timestamp (monotonic)

    // --- Statistics per stream ---
    uint64_t  accepted;              // packets accepted
    uint64_t  dropped;               // packets dropped
} stream_rule_t;

// ----------------------------
// In-memory stream table
// ----------------------------
typedef struct stream_table_s {
    stream_rule_t* rules; // dynamic array of rules
    uint32_t       count; // number of rules
} stream_table_t;

// ---------------------------------------------
// API: build, lookup, counters, cleanup
// ---------------------------------------------

/**
 * @brief Initialize the stream table from loaded configuration.
 *        - iterates config->stream_filters
 *        - resolves gate_id in config->stream_gates and meter_id in config->flow_meters
 *        - maps JSON fields into stream_rule_t
 *
 * @param table  [out] table to fill.
 * @param config [in]  configuration loaded by config_manager_load().
 */
void stream_table_init(stream_table_t* table, const config_data_t* config);

/**
 * @brief Find the rule that applies to a packet (exact match by MACs/VLAN/PCP).
 * @return pointer to rule if found; NULL otherwise.
 */
stream_rule_t* stream_table_lookup(stream_table_t* table, const struct packet_s* pkt);

/**
 * @brief Update per-stream counters centrally.
 */
void stream_table_update_counters(stream_table_t* table, stream_rule_t* rule, bool accepted);

/**
 * @brief Free memory associated to the table.
 */
void stream_table_cleanup(stream_table_t* table);

#endif // STREAM_TABLE_H
