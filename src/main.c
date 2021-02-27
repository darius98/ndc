#include <signal.h>

#include "app.h"
#include "conf/conf.h"
#include "logging/logging.h"

int main() {
    // Ignore sigpipe, since we handle broken pipe errors in code.
    signal(SIGPIPE, SIG_IGN);

    struct conf conf = load_conf();

    init_logging(&conf.logging);

    if (!conf.is_from_file) {
        LOG_INFO(
            "No conf file found at %s, using default settings. Use environment variable %s to point to a different "
            "conf file location instead.",
            conf.file_path, NDC_CONF_FILE_ENV_VAR);
    }

    run_ndc_application_sync(&conf);
    return 0;
}
