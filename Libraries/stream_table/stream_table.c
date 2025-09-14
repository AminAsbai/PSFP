// Libraries/stream_table/stream_table.c
#include "stream_table.h"
#include <stdlib.h>
#include <string.h>
#include "stream_table.h"
#include "packet_processor.h"  // now safe to include in .c


// -----------------------------
// Local helpers
// -----------------------------
static inline void mac_copy(uint8_t dst[6], const uint8_t src[6]) {
    memcpy(dst, src, 6);
}

static inline int mac_comparison(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6);
}

static const config_stream_gate_t* find_gate_by_id(const config_data_t* config, uint32_t gate_id) {
    if (!config || !config->stream_gates) return NULL;
    for (uint32_t i = 0; i < config->stream_gates_count; ++i) {
        if (config->stream_gates[i].gate_id == gate_id) return &config->stream_gates[i];
    }
    return NULL;
}

static const config_flow_meter_t* find_meter_by_id(const config_data_t* config, uint32_t meter_id) {
    if (!config || !config->flow_meters) return NULL;
    for (uint32_t i = 0; i < config->flow_meters_count; ++i) {
        if (config->flow_meters[i].meter_id == meter_id) return &config->flow_meters[i];
    }
    return NULL;
}

// -----------------------------
// Public API
// -----------------------------

void stream_table_init(stream_table_t* table, const config_data_t* config)
{
    if (!table) return;
    memset(table, 0, sizeof(*table));

    if (!config || config->stream_filters_count == 0 || !config->stream_filters) {
        // No rules — leave table empty
        return;
    }

    table->rules = (stream_rule_t*)calloc(config->stream_filters_count, sizeof(stream_rule_t));
    if (!table->rules) {
        table->count = 0;
        return;
    }
    table->count = config->stream_filters_count;

    for (uint32_t i = 0; i < table->count; ++i) {
        const config_stream_filter_t* f = &config->stream_filters[i];
        stream_rule_t*                r = &table->rules[i];

        // --- Identification (exact match: DMAC, SMAC, VLAN, PCP) ---
        mac_copy(r->id.dest_mac, f->match.dest_mac);
        mac_copy(r->id.src_mac,  f->match.src_mac);
        r->id.vlan_id = f->match.vlan_id;
        r->id.pcp     = f->match.pcp;

        // --- Filter enable: a filter entry becomes an active rule ---
        r->filter_enabled = true;

        // --- Resolve and map GATE (single non-wrapping window) ---
        const config_stream_gate_t* g = find_gate_by_id(config, f->gate_id);
        if (g && g->gate_enable && g->cycle_time_ns > 0 && g->gate_open_ns < g->gate_close_ns) {
            r->gate_enabled     = true;
            r->drop_when_closed = g->drop_when_closed;
            r->cycle_time_ns    = g->cycle_time_ns;
            r->gate_open_ns     = g->gate_open_ns;
            r->gate_close_ns    = g->gate_close_ns;
        } else {
            // Gate missing/disabled/invalid ⇒ treat as always open
            r->gate_enabled     = false;
            r->drop_when_closed = true;  // irrelevant when gate is disabled
            r->cycle_time_ns    = 0;
            r->gate_open_ns     = 0;
            r->gate_close_ns    = 0;
        }

        // --- Resolve and map METER (byte-based) ---
        const config_flow_meter_t* m = find_meter_by_id(config, f->meter_id);
        if (m && m->enable) {
            r->rate_bytes_per_s = m->rate_bps;    // JSON: bytes per second
            r->burst_bytes      = m->burst_bytes; // JSON: bytes
        } else {
            // Meter disabled or missing ⇒ unlimited
            r->rate_bytes_per_s = 0;
            r->burst_bytes      = 0;
        }

        // --- Policer runtime state ---
        // Start FULL to allow an initial burst up to burst_bytes (common policing behavior).
        // If unlimited (rate==0), tokens are irrelevant and left at 0.
        if (r->rate_bytes_per_s == 0 || r->burst_bytes == 0) {
            r->tokens_bytes = 0;
        } else {
            r->tokens_bytes = r->burst_bytes;
        }
        r->last_refresh_ns = 0; // your filter_engine will set a time base on first packet

        // --- Statistics ---
        r->accepted = 0;
        r->dropped  = 0;
    }
}

stream_rule_t* stream_table_lookup(stream_table_t* table, const packet_t* pkt)
{
    if (!table || !pkt || !table->rules) return NULL;

    for (uint32_t i = 0; i < table->count; ++i) {
        stream_rule_t* r = &table->rules[i];

        // Exact MAC match
        if (mac_comparison(pkt->dest_mac, r->id.dest_mac) != 0) continue;
        if (mac_comparison(pkt->src_mac,  r->id.src_mac)  != 0) continue;
    
        // If the packet has no VLAN tag, only match rules that expect none
        if (pkt->vlan_id != r->id.vlan_id) continue;
        if (pkt->pcp     != r->id.pcp)     continue;

        return r; // found
    }

    return NULL; // no match
}

void stream_table_update_counters(stream_table_t* table, stream_rule_t* rule, bool accepted)
{
    (void)table; // reserved for future locking/sharding
    if (!rule) return;
    if (accepted) {
        rule->accepted += 1;
    } else {
        rule->dropped  += 1;
    }
}

void stream_table_cleanup(stream_table_t* table)
{
    if (!table) return;
    if (table->rules) {
        free(table->rules);
        table->rules = NULL;
    }
    table->count = 0;
}
