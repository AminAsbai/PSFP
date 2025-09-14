// filter_engine.h
#ifndef FILTER_ENGINE_H
#define FILTER_ENGINE_H

#include <stdbool.h>
#include "stream_table.h"
#include "packet_processor.h"

// Initialize the filtering engine (if needed)
void filter_engine_init(void);

/**
 * @brief Apply PSFP filtering rules (policer + basic checks).
 *
 * - Uses rule->filter_enabled, rule->rate, rule->burst
 * - Updates runtime policer state (tokens, last_refresh_ns)
 * - Does NOT update per-stream counters (accepted/dropped)
 *
 * @param rule Pointer to the stream rule (must not be NULL)
 * @param pkt  Parsed packet (must not be NULL)
 * @return true if accepted, false if dropped
 */
bool filter_engine_apply(stream_rule_t* rule, const packet_t* pkt);

// Cleanup any dynamic memory or state (if needed)
void filter_engine_cleanup(void);

#endif // FILTER_ENGINE_H

