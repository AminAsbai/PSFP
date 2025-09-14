// main.c
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "config_manager.h"
#include "stream_table.h"
#include "packet_processor.h"
#include "nic_interface.h"
#include "stats.h"
#include "filter_engine.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: psfp_app <psfp_config.json>\n");
        return -1;
    }
    const char* config_path = argv[1];

    // 1) Load configuration
    config_data_t config;
    if (!config_manager_load(config_path, &config)) {
        printf("Failed to load config\n");
        return -1;
    }

    // 2) Init subsystems
    stats_init();
    filter_engine_init();

    stream_table_t stream_table;
    stream_table_init(&stream_table, &config);

    if (!nic_init()) {
        printf("NIC init failed\n");
        stream_table_cleanup(&stream_table);
        config_manager_cleanup(&config);
        return -1;
    }

    // 3) Main loop
    while (1) {
        uint8_t raw_frame[MAX_FRAME_SIZE];
        uint32_t raw_len = 0;

        if (nic_receive_raw(raw_frame, &raw_len)) {
            packet_t pkt;
            if (packet_processor_parse(raw_frame, raw_len, &pkt)) {
                bool accepted = psfp_process_packet(&stream_table, &pkt);
                // (Optional) Forward/drop: here just log result
                // In a real app, you'd nic_send(...) or hand to another stage.
                (void)accepted; // suppress unused warning for now
            } else {
                // parse failed, drop silently or log
            }
        }

        stats_update(); // optional periodic housekeeping
        // (Optional) stats_print(); on a timer or signal
    }

    // 4) Cleanup (usually not reached)
    nic_cleanup();
    stream_table_cleanup(&stream_table);
    filter_engine_cleanup();
    stats_cleanup();
    config_manager_cleanup(&config);
    return 0;
}
