#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <stdbool.h>
#include <stdint.h>

// DO NOT include stream_table.h here; just fwd-declare:
struct stream_table_s;

typedef struct packet_s {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t vlan_id;
    uint8_t  pcp;
    uint16_t length;
    uint8_t* payload;
} packet_t;

bool packet_processor_parse(const uint8_t* raw_data, uint32_t raw_len, packet_t* out_pkt);
bool psfp_process_packet(struct stream_table_s* table, const packet_t* pkt);

#endif // PACKET_PROCESSOR_H
