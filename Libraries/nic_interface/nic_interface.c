// nic_interface.c
#include "nic_interface.h"
#include <stdio.h>
#include <string.h>

// Initialize NIC
bool nic_init(void) {
    // TODO: replace with real NIC init
    printf("[nic] init (stub)\n");
    return true; // pretend NIC is always ready
}

// Receive a raw Ethernet frame (stub)
bool nic_receive_raw(uint8_t* buf, uint32_t* len) {
    // In a real implementation, fill buf with frame data
    // and write its length to *len. For now, no packets.
    (void)buf;
    (void)len;
    return false;
}

// Cleanup NIC
void nic_cleanup(void) {
    // TODO: close sockets or NIC resources
    printf("[nic] cleanup (stub)\n");
}
