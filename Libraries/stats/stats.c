// stats.c — super simple: only global totals
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "stats.h"
#include "stream_table.h"   // stream_rule_t

// ------------------- State -------------------
typedef struct {
    uint64_t total_packets;
    uint64_t accepted_packets;
    uint64_t dropped_packets;
} stats_global_t;

static stats_global_t G;

// ------------------- API -------------------
void stats_init(void) {
    memset(&G, 0, sizeof(G));
}

void stats_cleanup(void) {
    // nothing to clean up
}

void stats_update(void) {
    // no-op, kept for compatibility
}

void stats_update_packet(stream_rule_t* rule, bool accepted) {
    (void)rule; // not used for now
    G.total_packets++;
    if (accepted) {
        G.accepted_packets++;
    }
    else {
        G.dropped_packets++;
    }
}

void stats_print(void) {
    printf("=== Global Stats ===\n");
    printf("  Total   : %llu\n", (unsigned long long)G.total_packets);
    printf("  Accepted: %llu\n", (unsigned long long)G.accepted_packets);
    printf("  Dropped : %llu\n", (unsigned long long)G.dropped_packets);
    printf("====================\n");
}
