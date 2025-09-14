// filter_engine.c
#include "filter_engine.h"
#include <stdint.h>

// -----------------------------
// Monotonic time in nanoseconds
// -----------------------------
#if defined(_WIN32)
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  static uint64_t now_ns(void) {
      static LARGE_INTEGER freq = {0};
      LARGE_INTEGER counter;
      if (freq.QuadPart == 0) {
          QueryPerformanceFrequency(&freq);
      }
      QueryPerformanceCounter(&counter);
      return (uint64_t)((counter.QuadPart * 1000000000ULL) / (uint64_t)freq.QuadPart);
  }
#elif defined(__unix__) || defined(__APPLE__)
  #include <time.h>
  static uint64_t now_ns(void) {
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  }
#else
  #include <time.h>
  static uint64_t now_ns(void) {
      struct timespec ts;
      timespec_get(&ts, TIME_UTC);
      return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
  }
#endif

// -----------------------------
// Gate helper
// -----------------------------
// -----------------------------
// Gate helper (no wrapped windows)
// -----------------------------
static inline bool gate_is_open(const stream_rule_t* rule, uint64_t t_ns)
{
    if (!rule || !rule->gate_enabled || rule->cycle_time_ns == 0) {
        return true; // gate disabled => always open
    }

    const uint64_t period = rule->cycle_time_ns;
    const uint64_t open   = rule->gate_open_ns  % period;
    const uint64_t close  = rule->gate_close_ns % period;

    // Only allow normal, non-wrapping window: 0 <= open < close <= period
    if (open >= close) {
        // Invalid window -> treat as closed
        return false;
    }

    const uint64_t phase = t_ns % period; // position inside current cycle
    // Normal window: [open, close)
    return (phase >= open) && (phase < close);
}


// -----------------------------
// API implementation
// -----------------------------

void filter_engine_init(void) {
    // Nothing global to init for now
}

static bool policing_ok(stream_rule_t* rule, const packet_t* pkt) {
    // Sin límite -> siempre OK
    if (rule->rate_bytes_per_s == 0) {
        return true;
    }

    const uint64_t t = now_ns();

    // Init primera vez
    if (rule->last_refresh_ns == 0) {
        rule->last_refresh_ns = t;
        // Capacidad del bucket: si burst == 0, usa rate como capacidad por defecto
        const uint64_t capacity = (rule->burst_bytes == 0) ? rule->rate_bytes_per_s
                                                           : rule->burst_bytes;
        if (rule->tokens_bytes > capacity) {
            rule->tokens_bytes = capacity;
        }
    }

    // Refill
    const uint64_t dt_ns = t - rule->last_refresh_ns;
    if (dt_ns > 0) {
        const uint64_t add = (rule->rate_bytes_per_s * dt_ns) / 1000000000ULL;
        const uint64_t capacity = (rule->burst_bytes == 0) ? rule->rate_bytes_per_s
                                                           : rule->burst_bytes;

        uint64_t tokens = rule->tokens_bytes + add;
        if (tokens > capacity) tokens = capacity;

        rule->tokens_bytes = tokens;
        rule->last_refresh_ns = t;
    }

    // Consumo en bytes por paquete
    const uint64_t need = (uint64_t)pkt->length;

    if (rule->tokens_bytes >= need) {
        rule->tokens_bytes -= need;
        return true;
    }

    return false; // no hay tokens suficientes -> drop
}

bool filter_engine_apply(stream_rule_t* rule, const packet_t* pkt) {
    // Protection against seg fault
    if (!rule || !pkt) return false;

    // 1) Filter enabled?
    if (!rule->filter_enabled) {
        return false;
    }

    // 2) Gate (time window) check
    uint64_t t_now = 0;
#ifdef PACKET_HAS_TS_NS
    // If your packet parser provides a timestamp field (e.g., pkt->ts_ns)
    t_now = (pkt->ts_ns != 0) ? pkt->ts_ns : now_ns();
#else
    t_now = now_ns();
#endif

    if (!gate_is_open(rule, t_now)) {
        // PSFP behavior: drop when gate is closed
        // (Holding/buffering not implemented in this stage)
        if (rule->drop_when_closed) {
            return false;
        } else {
            // For now, same behavior (no buffer)
            return false;
        }
    }

    // 3) Policing (token bucket)
    if (!policing_ok(rule, pkt)) {
        return false;
    }

    // Passed checks → accepted
    return true;
}

void filter_engine_cleanup(void) {
    // Nothing global to clean for now
}
