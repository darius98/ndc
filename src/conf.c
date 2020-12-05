#include "conf.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* get_config_file_path() {
    const char* c = getenv(NDC_CONF_FILE_ENV_VAR);
    if (c != 0) {
        return c;
    }
    return "/etc/ndc/ndc.conf";
}

typedef void (*value_parser_t)(const char* file, int lineno, int colno, const char* value, void* dst);

struct conf_entry {
    const char* key;
    void* dst;
    value_parser_t parse;
    int loaded;
};

static int conf_entry_comp(const void* a, const void* b) {
    return strcmp(((const struct conf_entry*)a)->key, ((const struct conf_entry*)b)->key);
}

static void parse_conf_line(const char* file, int lineno, char* line, struct conf_entry* entries, int n_entries) {
    char* hash = strchr(line, '#');
    if (hash != 0) {
        *hash = 0;  // Ignore everything after hash as comment.
    }
    char* key = line;
    while (isspace(*key) != 0) {
        key++;
    }
    if (*key == '\0') {
        return;  // Whitespace and comments only on this line. Skip it.
    }
    char* value = key;
    // Parse until the end of the key.
    while (isspace(*value) == 0 && *value != '=') {
        value++;
    }
    int found_eq = (*value == '=');
    *value = '\0';  // Make the key null-terminated.
    value++;
    if (!found_eq) {
        while (isspace(*value) != 0) {
            value++;
        }
        if (*value != '=') {
            fprintf(stderr, "Conf file %s:%d:%d expected '='.", file, lineno, (int)((key - line) + strlen(key)));
            exit(EXIT_FAILURE);
        }
        value++;
    }
    while (isspace(*value) != 0) {
        value++;
    }
    // Find the entry with binary search (we sorted them lexicographically by key at the beginning)
    int left = 0, right = n_entries - 1;
    struct conf_entry* entry = 0;
    while (left <= right) {
        int middle = (left + right) / 2;
        int cmp = strcmp(key, entries[middle].key);
        if (cmp == 0) {
            entry = &entries[middle];
            break;
        } else if (cmp < 0) {
            right = middle - 1;
        } else {
            left = middle + 1;
        }
    }
    if (entry == 0) {
        fprintf(stderr, "Conf file %s:%d:1 unknown key '%s'.\n", file, lineno, key);
        exit(EXIT_FAILURE);
    }
    if (entry->loaded) {
        fprintf(stderr, "Conf file %s:%d:1 duplicate key '%s'.\n", file, lineno, key);
        exit(EXIT_FAILURE);
    }
    entry->parse(file, lineno, (int)(value - line + 1), value, entry->dst);
    entry->loaded = 1;
}

#define CONF_LINE_MAX_LEN 255
static int parse_conf_file(const char* path, struct conf_entry* entries, int n_entries) {
    qsort(entries, n_entries, sizeof(struct conf_entry), conf_entry_comp);
    FILE* conf_file = fopen(path, "r");
    if (conf_file == 0) {
        if (errno == ENOENT) {
            return 0;
        }
        fprintf(stderr, "Failed to open conf file at %s (errno=%d %s)\n", path, errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
    char buffer[CONF_LINE_MAX_LEN + 1];
    int lineno = 1;
    while (fgets(buffer, CONF_LINE_MAX_LEN + 1, conf_file) != 0) {
        if (buffer[strlen(buffer) - 1] != '\n') {
            fprintf(stderr, "Conf file %s:%d line too long. Max length supported is %d.\n", path, lineno,
                    CONF_LINE_MAX_LEN);
            exit(EXIT_FAILURE);
        }
        parse_conf_line(path, lineno, buffer, entries, n_entries);
        lineno++;
    }
    if (ferror(conf_file) != 0) {
        fprintf(stderr, "Encountered error while reading conf file at %s: ferror() returned %d\n", path,
                ferror(conf_file));
        exit(EXIT_FAILURE);
    }
    fclose(conf_file);
    return 1;
}
#undef CONF_LINE_MAX_LEN

static void parse_int(const char* file, int lineno, int colno, const char* value, void* dst) {
    errno = 0;
    char* end_ptr;
    long parsed = strtol(value, &end_ptr, 0);
    if (errno != 0) {
        fprintf(stderr, "Conf file %s:%d:%d invalid value (strtol() errno=%d %s).\n", file, lineno, colno, errno,
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (end_ptr == value) {
        fprintf(stderr, "Conf file %s:%d:%d invalid value\n", file, lineno, colno);
        exit(EXIT_FAILURE);
    }
    *((int*)dst) = (int)parsed;
}

static void parse_bool(const char* file, int lineno, int colno, const char* value, void* dst) {
    if (strncasecmp(value, "true", 4) == 0) {
        *((int*)dst) = 1;
    } else if (strncasecmp(value, "false", 5) == 0) {
        *((int*)dst) = 0;
    } else {
        fprintf(stderr, "Conf file %s:%d:%d invalid value (expected true or false)\n", file, lineno, colno);
        exit(EXIT_FAILURE);
    }
}

struct conf load_conf() {
    struct conf conf;
    conf.file_path = get_config_file_path();
    conf.logging.min_level = 0;
    conf.logging.filename_and_lineno = 1;
    conf.file_cache.num_buckets = 23;
    conf.file_cache.bucket_initial_capacity = 4;
    conf.tcp_server.backlog = 2048;
    conf.tcp_server.num_buckets = 23;
    conf.tcp_server.bucket_initial_capacity = 4;
    conf.tcp_server.events_batch_size = 2048;
    conf.tcp_server.connection_buffer_size = 65536;
    conf.tcp_write_queue.num_buckets = 23;
    conf.tcp_write_queue.bucket_initial_capacity = 4;
    conf.tcp_write_queue.events_batch_size = 2048;
    conf.http.num_workers = 1;
    conf.http.request_buffer_size = 65536;
#define NUM_CONF_ENTRIES 14
    struct conf_entry entries[NUM_CONF_ENTRIES] = {
        {"logging.min_level", &conf.logging.min_level, parse_int, 0},
        {"logging.filename_and_lineno", &conf.logging.filename_and_lineno, parse_bool, 0},
        {"file_cache.num_buckets", &conf.file_cache.num_buckets, parse_int, 0},
        {"file_cache.bucket_initial_capacity", &conf.file_cache.bucket_initial_capacity, parse_int, 0},
        {"tcp_server.backlog", &conf.tcp_server.backlog, parse_int, 0},
        {"tcp_server.num_buckets", &conf.tcp_server.num_buckets, parse_int, 0},
        {"tcp_server.bucket_initial_capacity", &conf.tcp_server.bucket_initial_capacity, parse_int, 0},
        {"tcp_server.events_batch_size", &conf.tcp_server.events_batch_size, parse_int, 0},
        {"tcp_server.connection_buffer_size", &conf.tcp_server.connection_buffer_size, parse_int, 0},
        {"tcp_write_queue.num_buckets", &conf.tcp_write_queue.num_buckets, parse_int, 0},
        {"tcp_write_queue.bucket_initial_capacity", &conf.tcp_write_queue.bucket_initial_capacity, parse_int, 0},
        {"tcp_write_queue.events_batch_size", &conf.tcp_write_queue.events_batch_size, parse_int, 0},
        {"http.request_buffer_size", &conf.http.request_buffer_size, parse_int, 0},
        {"http.num_workers", &conf.http.num_workers, parse_int, 0},
    };
    conf.is_from_file = parse_conf_file(conf.file_path, entries, NUM_CONF_ENTRIES);
#undef NUM_CONF_ENTRIES
    return conf;
}
