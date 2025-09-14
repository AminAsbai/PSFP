#include <stdio.h>
#include <direct.h>

#include "Unit/test_config_manager.h"
#include "Unit/test_stream_table.h"

int main(void) {
    char cwd[512];
    if (_getcwd(cwd, sizeof(cwd))) {
        printf("[DEBUG] Current working dir = %s\n", cwd);
    }

    printf("=== Running PSFP tests ===\n");
    int fails = 0;

    // Config Manager
    fails += suite_config_manager_run();

    // Stream Table
    fails += suite_stream_table_run();

    printf("=== Summary: %s ===\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}


