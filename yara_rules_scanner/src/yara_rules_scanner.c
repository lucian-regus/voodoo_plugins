#include "voodoo-av/infrastructure/plugin_interface.h"
#include "voodoo-av/domain/logger.h"
#include <yara.h>
#include "stdio.h"

static const char* COMPILED_YARA_FILE = "/var/lib/voodoo_av/compiled_rules.yarac";

static YR_RULES* rules = NULL;

static int plugin_init(void) {
    if (yr_initialize() != ERROR_SUCCESS) {
        log_message(LOG_LEVEL_ERROR, "YARA initialization failed.");
        return -1;
    }

    if (yr_rules_load(COMPILED_YARA_FILE, &rules) != ERROR_SUCCESS) {
        log_message(LOG_LEVEL_ERROR, "Failed to load compiled YARA rules from %s", COMPILED_YARA_FILE);
        return -1;
    }

    return 0;
}

static int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        int rule_id = 0;
        sscanf(rule->identifier, "rule_%d", &rule_id);
        *(int*)user_data = rule_id;
    }
    return CALLBACK_CONTINUE;
}

static int plugin_evaluate_file(char* filepath) {
    int matched_rule_id = 0;

    int result = yr_rules_scan_file(
        rules,
        filepath,
        0,
        yara_callback,
        &matched_rule_id,
        0
    );

    if (result != ERROR_SUCCESS) {
        log_message(LOG_LEVEL_ERROR, "YARA scan failed for file: %s\n", filepath);
        return 0;
    }

    return matched_rule_id;
}

static void plugin_cleanup(void) {
    if (rules) {
        yr_rules_destroy(rules);
        rules = NULL;
    }

    yr_finalize();

    log_message(LOG_LEVEL_INFO, "Yara Rules Scanner plugin unloaded.\n");
}

static Plugin plugin = {
    .name = "Yara Rules Scanner",
    .init = plugin_init,
    .evaluate_file = plugin_evaluate_file,
    .cleanup = plugin_cleanup
};

Plugin* get_plugin(void) {
    return &plugin;
}
