// packet_processor.c
#include "packet_processor.h"
#include "filter_engine.h"
#include "stream_table.h"
#include <string.h>     // for memcpy

// ------------------------------------------------------
// packet_processor_parse()
// ------------------------------------------------------
// Purpose:
//   Parse a raw Ethernet frame into a structured packet_t,
//   extracting key PSFP fields: MAC addresses, VLAN ID, PCP.
// Why:
//   PSFP rules need to know which stream the packet belongs to.
//   We can't make filtering decisions without extracting this data.
//
// Parameters:
//   raw_data - pointer to the start of the Ethernet frame
//   raw_len  - total length of the Ethernet frame
//   out_pkt  - pointer to a packet_t where parsed fields will be stored
//
// Returns:
//   true  - if parsing succeeded
//   false - if packet is too short or data invalid
//
bool packet_processor_parse(const uint8_t* raw_data, uint32_t raw_len, packet_t* out_pkt) {
    // Sanity checks
    if (!raw_data || !out_pkt || raw_len < 14) return false; // Ethernet header is 14 bytes min

    // Copy destination MAC (first 6 bytes)
    memcpy(out_pkt->dest_mac, raw_data, 6);

    // Copy source MAC (next 6 bytes)
    memcpy(out_pkt->src_mac,  raw_data + 6, 6);

    // Read EtherType (bytes 12-13)
    uint16_t eth_type = (uint16_t)((raw_data[12] << 8) | raw_data[13]);

    // VLAN-tagged frame (802.1Q)
    if (eth_type == 0x8100) {
        // Need at least 18 bytes for VLAN header
        if (raw_len < 18) return false;

        // VLAN Tag Control Information (TCI)
        uint16_t tci = (uint16_t)((raw_data[14] << 8) | raw_data[15]);

        // Extract Priority Code Point (PCP) = bits 15..13
        out_pkt->pcp     = (tci >> 13) & 0x7;

        // Extract VLAN ID = bits 11..0
        out_pkt->vlan_id = tci & 0x0FFF;

        // Payload starts after Ethernet (14) + VLAN (4) = 18 bytes
        out_pkt->payload = (uint8_t*)(raw_data + 18);

        // Payload length = total length - header length
        out_pkt->length  = (uint16_t)(raw_len - 18);

    } else {
        // Untagged frame
        out_pkt->pcp     = 0;
        out_pkt->vlan_id = 0;

        // Payload starts right after Ethernet header
        out_pkt->payload = (uint8_t*)(raw_data + 14);
        out_pkt->length  = (uint16_t)(raw_len - 14);
    }
    return true;
}

// ------------------------------------------------------
// psfp_process_packet()
// ------------------------------------------------------
// Purpose:
//   Execute the full PSFP pipeline for a parsed packet:
//   1. Stream identification via stream_table_lookup()
//   2. Apply filter and policing rules via filter_engine_apply()
//   3. Update packet statistics
//
// Parameters:
//   table - pointer to the active stream table
//   pkt   - parsed packet to process
//
// Returns:
//   true  - if packet passes filtering and is accepted
//   false - if packet is dropped
//
bool psfp_process_packet(struct stream_table_s* table, const packet_t* pkt) {
    // 0) Basic null-guard
    if (!table || !pkt) return false;

    // 1) Require VLAN tag: if parser left vlan_id/pcp at 0, treat as untagged -> drop
    //    (Assumes packet_processor_parse sets both to 0 when there is no 802.1Q header)
    if (pkt->vlan_id == 0 && pkt->pcp == 0) {
        // Untagged (or priority not provided) -> drop by policy
        stats_update_packet(NULL, false);
        return false;
    }

    // 2) Find matching stream rule
    stream_rule_t* rule = stream_table_lookup(table, pkt);
    if (!rule) {
        // No matching stream -> drop by default
        stats_update_packet(NULL, false);
        return true;
    }

    // 3) Apply PSFP (gate + meter)
    bool accepted = filter_engine_apply(rule, pkt);

    // 4) Update stats
    stats_update_packet(rule, accepted);
 
    return accepted;
}




