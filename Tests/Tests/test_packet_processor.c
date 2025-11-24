#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "packet_processor.h"
#include "stream_table.h"
#include "test_packet_processor.h"

// ---------------------------------------------------------------------------
// Mini framework (mismo estilo que test_stream_table.c)
// ---------------------------------------------------------------------------

static int g_failures_pp = 0;
static int g_block_failures = 0;

static void begin_block(const char* name) {
    (void)name;
    g_block_failures = 0;
}

static void check(bool cond) {
    if (!cond) {
        g_block_failures++;
        g_failures_pp++;
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

// ---------------------------------------------------------------------------
// STUBS para aislar psfp_process_packet()
//  - NO linkeas filter_engine.c, stats.c ni stream_table.c en este binario.
//  - Sólo compilas: packet_processor.c + este test.
// ---------------------------------------------------------------------------

// Fake tabla y regla
static stream_rule_t  g_fake_rule;
static stream_table_t g_fake_table;

// Control del comportamiento de los stubs
static bool g_lookup_returns_rule = false;
static bool g_filter_next_result = true;

// Monitoreo de llamadas
static int            g_stats_calls = 0;
static stream_rule_t* g_stats_last_rule = NULL;
static bool           g_stats_last_accepted = false;

static int            g_filter_calls = 0;
static stream_rule_t* g_filter_last_rule = NULL;
static const packet_t* g_filter_last_pkt = NULL;

// Prototipos esperados (coinciden con los headers reales)
bool filter_engine_apply(stream_rule_t* rule, const packet_t* pkt);
void stats_update_packet(stream_rule_t* rule, bool accepted);
stream_rule_t* stream_table_lookup(stream_table_t* table,
    const struct packet_s* pkt);

// Implementaciones stub
bool filter_engine_apply(stream_rule_t* rule, const packet_t* pkt) {
    g_filter_calls++;
    g_filter_last_rule = rule;
    g_filter_last_pkt = pkt;
    return g_filter_next_result;
}

void stats_update_packet(stream_rule_t* rule, bool accepted) {
    g_stats_calls++;
    g_stats_last_rule = rule;
    g_stats_last_accepted = accepted;
}

// Lookup muy simple controlado por bandera
stream_rule_t* stream_table_lookup(stream_table_t* table,
    const struct packet_s* pkt)
{
    (void)table;
    (void)pkt;
    return g_lookup_returns_rule ? &g_fake_rule : NULL;
}

// Helpers para resetear estado de stubs
static void reset_stubs(void) {
    g_lookup_returns_rule = false;
    g_filter_next_result = true;
    g_stats_calls = 0;
    g_stats_last_rule = NULL;
    g_stats_last_accepted = false;
    g_filter_calls = 0;
    g_filter_last_rule = NULL;
    g_filter_last_pkt = NULL;
}

// ---------------------------------------------------------------------------
// TESTS: packet_processor_parse()
// ---------------------------------------------------------------------------

// Frame untagged sencillo: EtherType IPv4, sin VLAN
static void test_parse_untagged(void) {
    begin_block("packet_processor_parse_untagged");

    uint8_t frame[] = {
        // DMAC
        0x01,0x02,0x03,0x04,0x05,0x06,
        // SMAC
        0x11,0x12,0x13,0x14,0x15,0x16,
        // EtherType = 0x0800 (IPv4)
        0x08,0x00,
        // Payload (3 bytes)
        0xAA,0xBB,0xCC
    };
    const uint32_t len = sizeof(frame);

    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    bool ok = packet_processor_parse(frame, len, &pkt);
    check(ok);

    if (ok) {
        // MACs
        check(memcmp(pkt.dest_mac, frame, 6) == 0);
        check(memcmp(pkt.src_mac, frame + 6, 6) == 0);

        // Sin VLAN
        check(pkt.vlan_id == 0);
        check(pkt.pcp == 0);

        // Payload y longitud
        check(pkt.payload == frame + 14);
        check(pkt.length == (uint16_t)(len - 14));
    }

    end_block("packet_processor_parse_untagged");
}

// Frame VLAN-tagged 802.1Q
static void test_parse_vlan_tagged(void) {
    begin_block("packet_processor_parse_vlan");

    // PCP = 5, VLAN ID = 123
    // TCI = (PCP<<13) | VLAN = (5<<13) | 123 = 0xA07B
    uint8_t frame[] = {
        // DMAC
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        // SMAC
        0x00,0x11,0x22,0x33,0x44,0x55,
        // EtherType = 0x8100 (802.1Q)
        0x81,0x00,
        // TCI = 0xA07B
        0xA0,0x7B,
        // Payload
        0xDE,0xAD,0xBE,0xEF
    };
    const uint32_t len = sizeof(frame);

    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    bool ok = packet_processor_parse(frame, len, &pkt);
    check(ok);

    if (ok) {
        check(memcmp(pkt.dest_mac, frame, 6) == 0);
        check(memcmp(pkt.src_mac, frame + 6, 6) == 0);

        check(pkt.pcp == 5);
        check(pkt.vlan_id == 123);

        check(pkt.payload == frame + 18);
        check(pkt.length == (uint16_t)(len - 18));
    }

    end_block("packet_processor_parse_vlan");
}

// Demasiado corto para cabecera Ethernet
static void test_parse_too_short(void) {
    begin_block("packet_processor_parse_too_short");

    uint8_t frame[10] = { 0 };
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    bool ok = packet_processor_parse(frame, sizeof(frame), &pkt);
    check(ok == false);

    end_block("packet_processor_parse_too_short");
}

// VLAN declarado pero sin espacio suficiente para TCI
static void test_parse_vlan_too_short(void) {
    begin_block("packet_processor_parse_vlan_too_short");

    uint8_t frame[16] = { 0 };
    // EtherType 0x8100 en bytes 12-13
    frame[12] = 0x81;
    frame[13] = 0x00;

    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    bool ok = packet_processor_parse(frame, sizeof(frame), &pkt);
    check(ok == false);

    end_block("packet_processor_parse_vlan_too_short");
}

// ---------------------------------------------------------------------------
// TESTS: psfp_process_packet()
// ---------------------------------------------------------------------------

static void test_psfp_untagged_dropped(void) {
    begin_block("psfp_process_packet_untagged");

    reset_stubs();

    // pkt sin VLAN (vlan=0, pcp=0)
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.vlan_id = 0;
    pkt.pcp = 0;

    bool res = psfp_process_packet(&g_fake_table, &pkt);
    check(res == false);

    // Debe llamar stats_update_packet(NULL, false) exactamente una vez
    check(g_stats_calls == 1);
    check(g_stats_last_rule == NULL);
    check(g_stats_last_accepted == false);

    // No debe llamar al filter_engine ni a stream_table_lookup
    check(g_filter_calls == 0);

    end_block("psfp_process_packet_untagged");
}

static void test_psfp_no_matching_stream(void) {
    begin_block("psfp_process_packet_no_match");

    reset_stubs();

    // Paquete con VLAN/PCP válidos
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.vlan_id = 10;
    pkt.pcp = 3;

    // Forzamos lookup a NO devolver regla
    g_lookup_returns_rule = false;

    bool res = psfp_process_packet(&g_fake_table, &pkt);

    // *** Comportamiento esperado: DROP por defecto (res == false) ***
    // Ojo: ahora mismo tu implementación devuelve true aquí,
    // por lo que este check FALLARÁ hasta que cambies:
    //   return true;  ->  return false;
    check(res == false);

    check(g_stats_calls == 1);
    check(g_stats_last_rule == NULL);
    check(g_stats_last_accepted == false);

    // filter_engine_apply no debe ser llamado si no hay regla
    check(g_filter_calls == 0);

    end_block("psfp_process_packet_no_match");
}

static void test_psfp_rule_accepts(void) {
    begin_block("psfp_process_packet_rule_accepts");

    reset_stubs();

    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.vlan_id = 10;
    pkt.pcp = 3;

    g_lookup_returns_rule = true;   // hay regla
    g_filter_next_result = true;   // policer la acepta

    bool res = psfp_process_packet(&g_fake_table, &pkt);
    check(res == true);

    check(g_filter_calls == 1);
    check(g_filter_last_rule == &g_fake_rule);
    check(g_filter_last_pkt == &pkt);

    check(g_stats_calls == 1);
    check(g_stats_last_rule == &g_fake_rule);
    check(g_stats_last_accepted == true);

    end_block("psfp_process_packet_rule_accepts");
}

static void test_psfp_rule_drops(void) {
    begin_block("psfp_process_packet_rule_drops");

    reset_stubs();

    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.vlan_id = 10;
    pkt.pcp = 3;

    g_lookup_returns_rule = true;
    g_filter_next_result = false;  // policer dropea

    bool res = psfp_process_packet(&g_fake_table, &pkt);
    check(res == false);

    check(g_filter_calls == 1);
    check(g_filter_last_rule == &g_fake_rule);
    check(g_filter_last_pkt == &pkt);

    check(g_stats_calls == 1);
    check(g_stats_last_rule == &g_fake_rule);
    check(g_stats_last_accepted == false);

    end_block("psfp_process_packet_rule_drops");
}

static void test_psfp_null_args(void) {
    begin_block("psfp_process_packet_null_args");

    reset_stubs();

    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.vlan_id = 10;
    pkt.pcp = 3;

    bool r1 = psfp_process_packet(NULL, &pkt);
    bool r2 = psfp_process_packet(&g_fake_table, NULL);

    check(r1 == false);
    check(r2 == false);

    // No debería tocar stats ni filter_engine
    check(g_stats_calls == 0);
    check(g_filter_calls == 0);

    end_block("psfp_process_packet_null_args");
}

// ---------------------------------------------------------------------------
// Entry point de la suite
// ---------------------------------------------------------------------------

int suite_packet_processor_run(void) {
    int fails_before = g_failures_pp;

    // Parsing
    test_parse_untagged();
    test_parse_vlan_tagged();
    test_parse_too_short();
    test_parse_vlan_too_short();

    // Pipeline PSFP
    test_psfp_untagged_dropped();
    test_psfp_no_matching_stream();
    test_psfp_rule_accepts();
    test_psfp_rule_drops();
    test_psfp_null_args();

    return g_failures_pp - fails_before;
}
