// Libraries/Config_Manager/config_manager.c
#include "config_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../cjson/cJSON.h"   // adjust include path if needed

// -----------------------------
// Internal helpers
// -----------------------------

static bool hex_val(char c, uint8_t* v) {
    if ('0' <= c && c <= '9') { *v = (uint8_t)(c - '0'); return true; }
    if ('a' <= c && c <= 'f') { *v = (uint8_t)(c - 'a' + 10); return true; }
    if ('A' <= c && c <= 'F') { *v = (uint8_t)(c - 'A' + 10); return true; }
    return false;
}

/**
 * Parse MAC string "AA:BB:CC:DD:EE:FF".
 * Also accepts '-' separators or no separators (12 hex digits continuous).
 * Empty/NULL string -> outputs 00:00:00:00:00:00 and returns true.
 */
static bool parse_mac_str(const char* s, uint8_t out[6]) {
    memset(out, 0, 6);
    if (!s || !*s) return true;

    char hexonly[32] = { 0 };
    size_t k = 0;
    for (const char* p = s; *p && k < sizeof(hexonly) - 1; ++p) {
        if (isxdigit((unsigned char)*p)) hexonly[k++] = *p;
    }
    if (k != 12) return false; // need exactly 12 hex digits

    for (int i = 0; i < 6; ++i) {
        uint8_t hi, lo;
        if (!hex_val(hexonly[2 * i], &hi) || !hex_val(hexonly[2 * i + 1], &lo)) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static const char* get_str(const cJSON* obj, const char* key) {
    const cJSON* s = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsString(s) ? s->valuestring : NULL;
}

static bool get_bool(const cJSON* obj, const char* key, bool defv) {
    const cJSON* b = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsBool(b))   return cJSON_IsTrue(b);
    if (cJSON_IsNumber(b)) return (b->valuedouble != 0.0);
    return defv;
}

static uint64_t get_u64(const cJSON* obj, const char* key, uint64_t defv) {
    const cJSON* n = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsNumber(n) && n->valuedouble >= 0) {
        return (uint64_t)(n->valuedouble);
    }
    return defv;
}

static uint32_t get_u32(const cJSON* obj, const char* key, uint32_t defv) {
    const cJSON* n = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsNumber(n) && n->valuedouble >= 0) {
        return (uint32_t)(n->valuedouble);
    }
    return defv;
}

static uint16_t get_u16(const cJSON* obj, const char* key, uint16_t defv) {
    const cJSON* n = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsNumber(n) && n->valuedouble >= 0) {
        return (uint16_t)(n->valuedouble);
    }
    return defv;
}

static uint8_t get_u8(const cJSON* obj, const char* key, uint8_t defv) {
    const cJSON* n = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsNumber(n) && n->valuedouble >= 0) {
        return (uint8_t)(n->valuedouble);
    }
    return defv;
}

// Helpers (C puro) para validar referencias
static bool has_gate_id(const config_data_t* cfg, uint32_t id) {
    for (uint32_t i = 0; i < cfg->stream_gates_count; ++i)
        if (cfg->stream_gates[i].gate_id == id) return true;
    return false;
}
static bool has_meter_id(const config_data_t* cfg, uint32_t id) {
    for (uint32_t i = 0; i < cfg->flow_meters_count; ++i)
        if (cfg->flow_meters[i].meter_id == id) return true;
    return false;
}

// -----------------------------
// Public API
// -----------------------------

bool config_manager_load(const char* path, config_data_t* out) {
    if (!path || !out) {
        printf("[config_manager] invalid args (path/out)\n");
        return false;
    }
    memset(out, 0, sizeof(*out));

    printf("[config_manager] opening file: %s\n", path);

    // Read entire file
    FILE* f = NULL;
#ifdef _WIN32
    fopen_s(&f, path, "rb");
#else
    f = fopen(path, "rb");
#endif
    if (!f) {
        printf("[config_manager] fopen failed\n");
        return false;
    }

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); printf("[config_manager] fseek end failed\n"); return false; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); printf("[config_manager] ftell failed\n"); return false; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); printf("[config_manager] fseek set failed\n"); return false; }

    char* buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); printf("[config_manager] malloc failed\n"); return false; }

    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); printf("[config_manager] fread mismatch\n"); return false; }
    buf[sz] = '\0';

    // Parse JSON
    cJSON* root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        printf("[config_manager] JSON parse failed\n");
        return false;
    }
    printf("[config_manager] JSON parsed OK\n");

    // ---------- stream_filters ----------
    const cJSON* j_filters = cJSON_GetObjectItemCaseSensitive(root, "stream_filters");
    if (!cJSON_IsArray(j_filters)) {
        printf("[config_manager] stream_filters missing or not array\n");
    }
    else {
        int n = cJSON_GetArraySize(j_filters);
        printf("[config_manager] stream_filters count=%d\n", n);
        if (n > 0) {
            out->stream_filters = (config_stream_filter_t*)calloc((size_t)n, sizeof(config_stream_filter_t));
            if (!out->stream_filters) { cJSON_Delete(root); printf("[config_manager] calloc filters failed\n"); return false; }
            out->stream_filters_count = (uint32_t)n;

            int i = 0;
            cJSON* it = NULL;
            cJSON_ArrayForEach(it, j_filters) {
                if (!cJSON_IsObject(it)) { continue; }
                config_stream_filter_t* dst = &out->stream_filters[i];
                dst->stream_id = get_u32(it, "stream_id", 0);
                printf("[config_manager] filter[%d] stream_id=%u\n", i, dst->stream_id);

                const cJSON* j_match = cJSON_GetObjectItemCaseSensitive(it, "match");
                if (cJSON_IsObject(j_match)) {
                    const char* dmac = get_str(j_match, "dest_mac");
                    const char* smac = get_str(j_match, "src_mac");
                    printf("[config_manager]  dest_mac=%s src_mac=%s\n", dmac ? dmac : "(null)", smac ? smac : "(null)");
                    parse_mac_str(dmac, dst->match.dest_mac);
                    parse_mac_str(smac, dst->match.src_mac);
                    dst->match.vlan_id = get_u16(j_match, "vlan_id", 0);
                    dst->match.pcp = get_u8(j_match, "pcp", 0);
                    printf("[config_manager]  vlan=%u pcp=%u\n", dst->match.vlan_id, dst->match.pcp);
                }

                dst->gate_id = get_u32(it, "gate_id", 0);
                dst->meter_id = get_u32(it, "meter_id", 0);
                printf("[config_manager]  gate_id=%u meter_id=%u\n", dst->gate_id, dst->meter_id);

                if (++i >= n) break;
            }
        }
    }

    // ---------- stream_gates ----------
    const cJSON* j_gates = cJSON_GetObjectItemCaseSensitive(root, "stream_gates");
    if (!cJSON_IsArray(j_gates)) {
        printf("[config_manager] stream_gates missing or not array\n");
    }
    else {
        int n = cJSON_GetArraySize(j_gates);
        printf("[config_manager] stream_gates count=%d\n", n);
        if (n > 0) {
            out->stream_gates = (config_stream_gate_t*)calloc((size_t)n, sizeof(config_stream_gate_t));
            if (!out->stream_gates) {
                free(out->stream_filters); out->stream_filters = NULL; out->stream_filters_count = 0;
                cJSON_Delete(root);
                printf("[config_manager] calloc gates failed\n");
                return false;
            }
            out->stream_gates_count = (uint32_t)n;
            int i = 0;
            cJSON* it = NULL;
            cJSON_ArrayForEach(it, j_gates) {
                if (!cJSON_IsObject(it)) { continue; }
                config_stream_gate_t* dst = &out->stream_gates[i];

                dst->gate_id = get_u32(it, "gate_id", 0);
                dst->gate_enable = get_bool(it, "gate_enable", false);
                // JSON accepts "drop_when_close" or "drop_when_closed"
                bool dwc_a = get_bool(it, "drop_when_closed", false);
                bool dwc_b = get_bool(it, "drop_when_close", false);
                dst->drop_when_closed = (dwc_a || dwc_b);
                dst->cycle_time_ns = get_u64(it, "cycle_time_ns", 0);
                dst->gate_open_ns = get_u64(it, "gate_open_ns", 0);
                dst->gate_close_ns = get_u64(it, "gate_close_ns", 0);

                // Sanity: non-wrapping window; if invalid, disable gate
                if (dst->gate_enable && dst->cycle_time_ns > 0 &&
                    dst->gate_open_ns >= dst->gate_close_ns) {
                    printf("[config_manager] gate[%d] invalid window -> disabling gate\n", i);
                    dst->gate_enable = false;
                }

                printf("[config_manager] gate[%d] id=%u enable=%d drop=%d cycle=%llu open=%llu close=%llu\n",
                    i, dst->gate_id, dst->gate_enable, dst->drop_when_closed,
                    (unsigned long long)dst->cycle_time_ns,
                    (unsigned long long)dst->gate_open_ns,
                    (unsigned long long)dst->gate_close_ns);

                if (++i >= n) break;
            }
        }
    }

    // ---------- flow_meters ----------
    const cJSON* j_meters = cJSON_GetObjectItemCaseSensitive(root, "flow_meters");
    if (!cJSON_IsArray(j_meters)) {
        printf("[config_manager] flow_meters missing or not array\n");
    }
    else {
        int n = cJSON_GetArraySize(j_meters);
        printf("[config_manager] flow_meters count=%d\n", n);
        if (n > 0) {
            out->flow_meters = (config_flow_meter_t*)calloc((size_t)n, sizeof(config_flow_meter_t));
            if (!out->flow_meters) {
                free(out->stream_filters); out->stream_filters = NULL; out->stream_filters_count = 0;
                free(out->stream_gates);   out->stream_gates = NULL; out->stream_gates_count = 0;
                cJSON_Delete(root);
                printf("[config_manager] calloc meters failed\n");
                return false;
            }
            out->flow_meters_count = (uint32_t)n;
            int i = 0;
            cJSON* it = NULL;
            cJSON_ArrayForEach(it, j_meters) {
                if (!cJSON_IsObject(it)) { continue; }
                config_flow_meter_t* dst = &out->flow_meters[i];

                dst->meter_id = get_u32(it, "meter_id", 0);
                dst->enable = get_bool(it, "enable", false);
                dst->rate_bps = get_u64(it, "rate_bps", 0);
                dst->burst_bytes = get_u64(it, "burst_bytes", 0);

                printf("[config_manager] meter[%d] id=%u enable=%d rate=%llu burst=%llu\n",
                    i, dst->meter_id, dst->enable,
                    (unsigned long long)dst->rate_bps,
                    (unsigned long long)dst->burst_bytes);

                if (++i >= n) break;
            }
        }
    }

    // ---------- cross-reference validation ----------
    {
        bool ok = true;
        for (uint32_t i = 0; i < out->stream_filters_count; ++i) {
            const config_stream_filter_t* f = &out->stream_filters[i];

            if (f->gate_id && !has_gate_id(out, f->gate_id)) {
                printf("[config_manager] ERROR: filter[%u] references missing gate_id=%u\n", i, f->gate_id);
                ok = false; break;
            }
            if (f->meter_id && !has_meter_id(out, f->meter_id)) {
                printf("[config_manager] ERROR: filter[%u] references missing meter_id=%u\n", i, f->meter_id);
                ok = false; break;
            }
        }

        if (!ok) {
            // Cleanup on failure
            cJSON_Delete(root);
            free(out->stream_filters); out->stream_filters = NULL; out->stream_filters_count = 0;
            free(out->stream_gates);   out->stream_gates = NULL; out->stream_gates_count = 0;
            free(out->flow_meters);    out->flow_meters = NULL; out->flow_meters_count = 0;
            printf("[config_manager] load FAILED due to missing references\n");
            return false;
        }
    }

    cJSON_Delete(root);
    printf("[config_manager] load SUCCESS\n");
    return true;
}

void config_manager_cleanup(config_data_t* config) {
    if (!config) return;

    free(config->stream_filters);
    free(config->stream_gates);
    free(config->flow_meters);

    config->stream_filters = NULL;
    config->stream_gates = NULL;
    config->flow_meters = NULL;

    config->stream_filters_count = 0;
    config->stream_gates_count = 0;
    config->flow_meters_count = 0;
}
