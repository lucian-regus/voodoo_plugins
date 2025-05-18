#include <stdio.h>
#include <stdlib.h>
#include <domain/logger.h>

#include "voodoo/infrastructure/plugin_interface.h"

#define NFT_FILE_PATH "/var/lib/voodoo/blacklist.nft"

static int run_command(const char* cmd) {
    int ret = system(cmd);
    if (ret != 0) {
        log_message(LOG_LEVEL_ERROR, "Command failed: %s\n", cmd);
    }

    return ret;
}

static int plugin_init(void) {
    if (system("sudo /usr/sbin/nft flush ruleset") != 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to flush nftables ruleset\n");
        return -1;
    }

    char command[512];
    snprintf(command, sizeof(command), "sudo /usr/sbin/nft -f %s", NFT_FILE_PATH);
    if (system(command) != 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to load nftables ruleset from file\n");
        return -1;
    }

    return 0;
}

static int plugin_evaluate_file(char* filepath) {
    return 0;
}

static void plugin_cleanup(void) {
    if (system("sudo /usr/sbin/nft flush ruleset") != 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to flush nftables ruleset\n");
    }
}

static Plugin plugin = {
    .name = "IP Blocker",
    .init = plugin_init,
    .evaluate_file = plugin_evaluate_file,
    .cleanup = plugin_cleanup
};

Plugin* get_plugin(void) {
    return &plugin;
}
