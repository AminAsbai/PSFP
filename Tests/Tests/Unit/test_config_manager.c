#include <stdio.h>
#include <stdbool.h>
#include "config_manager.h"

static int g_failures = 0;

static void check_true(const char* name, bool cond) {
    if (cond) {
        printf("[OK] %s\n", name);
    }
    else {
        printf("[FAIL] %s\n", name);
        g_failures++;
    }
}

int suite_config_manager_run(void) {
    // 1) Valid
    {
        config_data_t cfg;
        bool ok = config_manager_load("Fixture/psfp-config.valid.json", &cfg);
        check_true("valid config loads", ok);
        if (ok) config_manager_cleanup(&cfg);
    }
    // 2) Invalid
    {
        config_data_t cfg;
        bool ok = config_manager_load("Fixture/psfp-config.missing-gate.json", &cfg);
        check_true("invalid config rejected", !ok);
        if (ok) config_manager_cleanup(&cfg); // just in case your loader returns true
    }
    return g_failures;
}
