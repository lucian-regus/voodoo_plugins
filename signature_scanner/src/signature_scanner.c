#include "voodoo/infrastructure/plugin_interface.h"
#include "voodoo/infrastructure/context.h"
#include "voodoo/domain/database.h"
#include "voodoo/domain/logger.h"
#include "voodoo/domain/mappers.h"
#include "signature_scanner/helpers.h"

#include "glib.h"
#include "stdio.h"
#include "string.h"

static int plugin_init(void) {
    return 0;
}

static int plugin_evaluate_file(char* filepath) {
    GlobalContext* global_context = get_context();
    if (!global_context) {
        log_message(LOG_LEVEL_ERROR,"Global context is NULL.\n");
        return 0;
    }

    char hash[65];
    if (!hash_file(filepath, hash)) {
        log_message(LOG_LEVEL_ERROR,"[ERROR] Failed to hash file: %s\n", filepath);
        return 0;
    }

    GList* params = g_list_append(NULL, g_strdup(hash));
    if (!params) {
       log_message(LOG_LEVEL_ERROR,"[ERROR] Failed to build query parameters.\n");
        return 0;
    }

    GList* result = run_query(
        global_context->database_context,
        "SELECT id FROM malware_signatures WHERE signature = $1 LIMIT 1",
        params,
        id_row_mapper
    );

    int matched_id = 0;

    if (result && result->data) {
        matched_id = atoi(result->data);
    }

    g_list_free_full(result, g_free);
    return matched_id;
}


static void plugin_cleanup(void) {
    log_message(LOG_LEVEL_INFO, "Signature Scanner plugin unloaded.\n");
}

static Plugin plugin = {
    .name = "Signature Scanner",
    .init = plugin_init,
    .evaluate_file = plugin_evaluate_file,
    .cleanup = plugin_cleanup
};

Plugin* get_plugin(void) {
    return &plugin;
}
