// stats.h
#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <stdbool.h>
#include "stream_table.h"   // brings stream_rule_t (avoid tag forward here)

/**
 * @brief Initialize the statistics module.
 * Call once at startup to set up data structures or reset counters.
 */
void stats_init(void);

/**
 * @brief Update statistics for a processed packet.
 * Call after each packet is processed.
 *
 * @param rule     Pointer to the matching stream rule (NULL if no match)
 * @param accepted true if the packet was accepted, false if dropped
 */
void stats_update_packet(stream_rule_t* rule, bool accepted);

/**
 * @brief Print current statistics to standard output or log.
 */
void stats_print(void);

/**
 * @brief Clean up resources used by statistics.
 */
void stats_cleanup(void);

#endif // STATS_H
