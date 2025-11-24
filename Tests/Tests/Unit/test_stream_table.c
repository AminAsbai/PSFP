#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "config_manager.h"
#include "stream_table.h"
#include "packet_processor.h"
#include "test_stream_table.h"

// ---------------------------------------------------------------------------
// Minimal test framework: one line per logical test block
// ---------------------------------------------------------------------------

static int g_failures_stream = 0;
static int g_block_failures = 0;

static void begin_block(const char* name) {
    (void)name; // not used inside, but kept for symmetry
    g_block_failures = 0;
}

static void check(bool cond) {
    if (!cond) {
        g_block_failures++;
        g_failures_stream++;
    }
}

static void end_block(const char* name) {
    if (g_block_failures == 0) {
        printf("[OK]   %s\n", name);
    }
    else {
        printf("[FAIL] %s (%d errors)\n", name, g_block_failures);
    }
}

static void set_mac(uint8_t dst[6], const uint8_t src[6]) {
    memcpy(dst, src, 6);
}

// ---------------------------------------------------------------------------
// Packet helpers: MUST match psfp-config.valid.json
// ---------------------------------------------------------------------------
//
// JSON (psfp-config.valid.json):
//  stream_filters[0]:
//    dest_mac: 01:80:C2:00:00:0E
//    src_mac : 02:42:AC:11:00:02
//    vlan_id : 10
//    pcp     : 3
//    gate_id : 10  (enabled, drop_when_closed=true)
//    meter_id: 20  (enabled, rate_bps=2e6, burst=16000)
//
//  stream_filters[1]:
//    dest_mac: 01:80:C2:00:00:0E
//    src_mac : 02:42:AC:11:00:03
//    vlan_id : 10
//    pcp     : 5
//    gate_id : 10  (same gate as stream 0)
//    meter_id: 20  (same meter as stream 0)
//
//  stream_filters[2]:
//    dest_mac: 01:80:C2:00:00:10
//    src_mac : 02:42:AC:11:00:04
//    vlan_id : 30
//    pcp     : 1
//    gate_id : 11  (disabled)
//    meter_id: 21  (disabled)
// ---------------------------------------------------------------------------

// Stream 1 (shared gate/meter)
static void make_matching_packet_rule1(packet_t* pkt) {
    memset(pkt, 0, sizeof(*pkt));
    const uint8_t dmac[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
    const uint8_t smac[6] = { 0x02, 0x42, 0xAC, 0x11, 0x00, 0x02 };
    set_mac(pkt->dest_mac, dmac);
    set_mac(pkt->src_mac, smac);
    pkt->vlan_id = 10;
    pkt->pcp = 3;
}

// Stream 2 (same gate/meter as stream 1, different SMAC/PCP)
static void make_matching_packet_rule2(packet_t* pkt) {
    memset(pkt, 0, sizeof(*pkt));
    const uint8_t dmac[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
    const uint8_t smac[6] = { 0x02, 0x42, 0xAC, 0x11, 0x00, 0x03 };
    set_mac(pkt->dest_mac, dmac);
    set_mac(pkt->src_mac, smac);
    pkt->vlan_id = 10;
    pkt->pcp = 5;
}

// Stream 3 (separate gate/meter, both disabled)
static void make_matching_packet_rule3(packet_t* pkt) {
    memset(pkt, 0, sizeof(*pkt));
    const uint8_t dmac[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x10 };
    const uint8_t smac[6] = { 0x02, 0x42, 0xAC, 0x11, 0x00, 0x04 };
    set_mac(pkt->dest_mac, dmac);
    set_mac(pkt->src_mac, smac);
    pkt->vlan_id = 30;
    pkt->pcp = 1;
}

// Non-matching packet (same MACs as rule1, different VLAN)
static void make_nonmatching_packet_vlan(packet_t* pkt) {
    memset(pkt, 0, sizeof(*pkt));
    const uint8_t dmac[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
    const uint8_t smac[6] = { 0x02, 0x42, 0xAC, 0x11, 0x00, 0x02 };
    set_mac(pkt->dest_mac, dmac);
    set_mac(pkt->src_mac, smac);
    pkt->vlan_id = 999;   // different from 10
    pkt->pcp = 3;
}

// Untagged packet (vlan=0, pcp=0) which should not match any rule in this fixture
static void make_untagged_packet(packet_t* pkt) {
    memset(pkt, 0, sizeof(*pkt));
    const uint8_t dmac[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
    const uint8_t smac[6] = { 0x02, 0x42, 0xAC, 0x11, 0x00, 0x02 };
    set_mac(pkt->dest_mac, dmac);
    set_mac(pkt->src_mac, smac);
    pkt->vlan_id = 0;
    pkt->pcp = 0;
}

// ---------------------------------------------------------------------------
// Test suite entry point
// ---------------------------------------------------------------------------

int suite_stream_table_run(void) {
    int fails_before = g_failures_stream;

    config_data_t  cfg;
    stream_table_t table;

    // --------------------------------------------------------------
    // 1) stream_table_init: load config + build table + map fields
    // --------------------------------------------------------------
    begin_block("stream_table_init");

    bool ok = config_manager_load("Fixture/psfp-config.valid.json", &cfg);
    check(ok);

    if (ok) {
        memset(&table, 0, sizeof(table));
        stream_table_init(&table, &cfg);

        // Expect 3 rules according to the JSON
        check(table.count == 3);
        check(table.rules != NULL);

        if (table.rules && table.count == 3) {
            // --- Rule 0: stream 1001, gate 10, meter 20 ---
            stream_rule_t* r0 = &table.rules[0];
            const uint8_t r0_dmac[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
            const uint8_t r0_smac[6] = { 0x02, 0x42, 0xAC, 0x11, 0x00, 0x02 };

            check(memcmp(r0->id.dest_mac, r0_dmac, 6) == 0);
            check(memcmp(r0->id.src_mac, r0_smac, 6) == 0);
            check(r0->id.vlan_id == 10);
            check(r0->id.pcp == 3);

            check(r0->gate_enabled == true);
            check(r0->drop_when_closed == true);
            check(r0->cycle_time_ns == 1000000ULL);
            check(r0->gate_open_ns == 200000ULL);
            check(r0->gate_close_ns == 800000ULL);

            check(r0->filter_enabled == true);
            check(r0->rate_bytes_per_s == 2000000ULL);
            check(r0->burst_bytes == 16000ULL);

            if (r0->rate_bytes_per_s == 0 || r0->burst_bytes == 0) {
                check(r0->tokens_bytes == 0);
            }
            else {
                check(r0->tokens_bytes == r0->burst_bytes);
            }
            check(r0->last_refresh_ns == 0);
            check(r0->accepted == 0);
            check(r0->dropped == 0);

            // --- Rule 1: stream 1002, SAME gate/meter as r0 ---
            stream_rule_t* r1 = &table.rules[1];
            const uint8_t r1_dmac[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
            const uint8_t r1_smac[6] = { 0x02, 0x42, 0xAC, 0x11, 0x00, 0x03 };

            check(memcmp(r1->id.dest_mac, r1_dmac, 6) == 0);
            check(memcmp(r1->id.src_mac, r1_smac, 6) == 0);
            check(r1->id.vlan_id == 10);
            check(r1->id.pcp == 5);

            // same gate/meter configuration as r0
            check(r1->gate_enabled == r0->gate_enabled);
            check(r1->drop_when_closed == r0->drop_when_closed);
            check(r1->cycle_time_ns == r0->cycle_time_ns);
            check(r1->gate_open_ns == r0->gate_open_ns);
            check(r1->gate_close_ns == r0->gate_close_ns);

            check(r1->filter_enabled == true);
            check(r1->rate_bytes_per_s == r0->rate_bytes_per_s);
            check(r1->burst_bytes == r0->burst_bytes);

            if (r1->rate_bytes_per_s == 0 || r1->burst_bytes == 0) {
                check(r1->tokens_bytes == 0);
            }
            else {
                check(r1->tokens_bytes == r1->burst_bytes);
            }
            check(r1->last_refresh_ns == 0);
            check(r1->accepted == 0);
            check(r1->dropped == 0);

            // --- Rule 2: stream 1003, gate 11 disabled, meter 21 disabled ---
            stream_rule_t* r2 = &table.rules[2];
            const uint8_t r2_dmac[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x10 };
            const uint8_t r2_smac[6] = { 0x02, 0x42, 0xAC, 0x11, 0x00, 0x04 };

            check(memcmp(r2->id.dest_mac, r2_dmac, 6) == 0);
            check(memcmp(r2->id.src_mac, r2_smac, 6) == 0);
            check(r2->id.vlan_id == 30);
            check(r2->id.pcp == 1);

            // gate 11 disabled -> gate_enabled false, times 0 (per stream_table.c)
            check(r2->gate_enabled == false);
            check(r2->cycle_time_ns == 0);
            check(r2->gate_open_ns == 0);
            check(r2->gate_close_ns == 0);

            // meter 21 disabled -> rate/burst/tokens = 0
            check(r2->rate_bytes_per_s == 0);
            check(r2->burst_bytes == 0);
            check(r2->tokens_bytes == 0);

            check(r2->last_refresh_ns == 0);
            check(r2->accepted == 0);
            check(r2->dropped == 0);
        }
    }

    end_block("stream_table_init");

    // If we couldn't load config, no point in continuing
    if (!ok) {
        return g_failures_stream - fails_before;
    }

    // --------------------------------------------------------------
    // 2) stream_table_lookup: match, non-match, untagged
    // --------------------------------------------------------------
    begin_block("stream_table_lookup");

    {
        packet_t p1, p2, p3;
        make_matching_packet_rule1(&p1);
        make_matching_packet_rule2(&p2);
        make_matching_packet_rule3(&p3);

        stream_rule_t* r1 = stream_table_lookup(&table, &p1);
        stream_rule_t* r2 = stream_table_lookup(&table, &p2);
        stream_rule_t* r3 = stream_table_lookup(&table, &p3);

        check(r1 != NULL);
        check(r2 != NULL);
        check(r3 != NULL);

        if (r1) {
            check(r1->id.vlan_id == p1.vlan_id);
            check(r1->id.pcp == p1.pcp);
        }
        if (r2) {
            check(r2->id.vlan_id == p2.vlan_id);
            check(r2->id.pcp == p2.pcp);
        }
        if (r3) {
            check(r3->id.vlan_id == p3.vlan_id);
            check(r3->id.pcp == p3.pcp);
        }
    }

    // Non-match: wrong VLAN
    {
        packet_t pkt;
        make_nonmatching_packet_vlan(&pkt);
        stream_rule_t* r = stream_table_lookup(&table, &pkt);
        check(r == NULL);
    }

    // Untagged: should not match any rule in this fixture
    {
        packet_t pkt;
        make_untagged_packet(&pkt);
        stream_rule_t* r = stream_table_lookup(&table, &pkt);
        check(r == NULL);
    }

    end_block("stream_table_lookup");

    // --------------------------------------------------------------
    // 3) stream_table_update_counters
    // --------------------------------------------------------------
    begin_block("stream_table_update_counters");

    {
        packet_t pkt;
        make_matching_packet_rule1(&pkt);
        stream_rule_t* r = stream_table_lookup(&table, &pkt);
        check(r != NULL);

        if (r) {
            uint64_t acc0 = r->accepted;
            uint64_t drop0 = r->dropped;

            stream_table_update_counters(&table, r, true);  // accepted
            stream_table_update_counters(&table, r, false); // dropped
            stream_table_update_counters(&table, r, false); // dropped again

            check(r->accepted == acc0 + 1);
            check(r->dropped == drop0 + 2);
        }
    }

    end_block("stream_table_update_counters");

    // --------------------------------------------------------------
    // 4) stream_table_sanity: general invariants
    // --------------------------------------------------------------
    begin_block("stream_table_sanity");

    {
        check(table.count >= 1);

        for (uint32_t i = 0; i < table.count; ++i) {
            stream_rule_t* r = &table.rules[i];
            check(r->id.vlan_id <= 4095);
            check(r->id.pcp <= 7);
        }
    }

    end_block("stream_table_sanity");

    // --------------------------------------------------------------
    // Cleanup
    // --------------------------------------------------------------
    stream_table_cleanup(&table);
    config_manager_cleanup(&cfg);

    return g_failures_stream - fails_before;
}
