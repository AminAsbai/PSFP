#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "config_manager.h"
#include "stream_table.h"
#include "packet_processor.h"   // Asegúrate de que define packet_t con dest_mac, src_mac, vlan_id, pcp
#include "test_stream_table.h"

// --- mini asertos “soft” locales ---
static int g_failures_stream = 0;
static void check_true_st(const char* name, bool cond) {
    if (cond) printf("[OK] %s\n", name);
    else { printf("[FAIL] %s\n", name); g_failures_stream++; }
}

// helper: setea MAC con bytes literales
static void set_mac(uint8_t dst[6], const uint8_t src[6]) { memcpy(dst, src, 6); }

// Paquete que DEBE hacer match con la 1ª regla del fixture válido
// dest=01:80:C2:00:00:0E, src=02:42:AC:11:00:02, vlan=10, pcp=3
static void make_matching_packet_rule1(packet_t* pkt) {
    memset(pkt, 0, sizeof(*pkt));
    const uint8_t dmac[6] = { 0x01,0x80,0xC2,0x00,0x00,0x0E };
    const uint8_t smac[6] = { 0x02,0x42,0xAC,0x11,0x00,0x02 };
    set_mac(pkt->dest_mac, dmac);
    set_mac(pkt->src_mac, smac);
    pkt->vlan_id = 10;
    pkt->pcp = 3;
}

// Paquete que NO debe hacer match (vlan diferente)
static void make_nonmatching_packet(packet_t* pkt) {
    memset(pkt, 0, sizeof(*pkt));
    const uint8_t dmac[6] = { 0x01,0x80,0xC2,0x00,0x00,0x0E };
    const uint8_t smac[6] = { 0x02,0x42,0xAC,0x11,0x00,0x02 };
    set_mac(pkt->dest_mac, dmac);
    set_mac(pkt->src_mac, smac);
    pkt->vlan_id = 999; // distinto a 10
    pkt->pcp = 3;
}

int suite_stream_table_run(void) {
    int fails_before = g_failures_stream;

    // 1) Cargar config válida
    config_data_t cfg;
    bool ok = config_manager_load("Fixture/psfp-config.valid.json", &cfg);
    check_true_st("config_manager_load(valid) for stream_table", ok);
    if (!ok) return ++g_failures_stream; // sin config no seguimos

    // 2) Inicializar stream_table
    stream_table_t table;
    memset(&table, 0, sizeof(table));
    stream_table_init(&table, &cfg);

    // 3) Lookup que debe encontrar
    {
        packet_t pkt;
        make_matching_packet_rule1(&pkt);
        stream_rule_t* r = stream_table_lookup(&table, &pkt);
        check_true_st("stream_table_lookup exact match returns non-NULL", (r != NULL));
    }

    // 4) Lookup que NO debe encontrar
    {
        packet_t pkt;
        make_nonmatching_packet(&pkt);
        stream_rule_t* r = stream_table_lookup(&table, &pkt);
        check_true_st("stream_table_lookup non-match returns NULL", (r == NULL));
    }

    // 5) Limpieza
    stream_table_cleanup(&table);
    config_manager_cleanup(&cfg);

    return g_failures_stream - fails_before;
}
