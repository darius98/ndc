#include "tls.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string.h>

#include "logging/logging.h"

static int print_errors(const char* str, __attribute__((unused)) size_t len, __attribute__((unused)) void* u) {
    // The OpenSSL error always contains an extra newline
    *((char*)str + strlen(str) - 1) = '\0';
    LOG_ERROR("OpenSSL: %s", str);
    *((char*)str + strlen(str)) = '\n';
    return 0;
}

void* init_tls(char* cert_pem_file) {
    if (strncasecmp(cert_pem_file, "none", 4) == 0) {
        return 0;
    }

    SSL_library_init();

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (ctx == 0) {
        ERR_print_errors_cb(print_errors, 0);
        LOG_FATAL("Failed to initialize OpenSSL certificates.");
    }
    if (SSL_CTX_use_certificate_file(ctx, cert_pem_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_cb(print_errors, 0);
        LOG_FATAL("Failed to initialize OpenSSL certificates.");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, cert_pem_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_cb(print_errors, 0);
        LOG_FATAL("Failed to initialize OpenSSL certificates.");
    }
    if (SSL_CTX_check_private_key(ctx) == 0) {
        ERR_print_errors_cb(print_errors, 0);
        LOG_FATAL("Failed to initialize OpenSSL certificates.");
    }
    return ctx;
}

void* new_tls_for_conn(void* tls_ctx, int fd) {
    SSL* tls = SSL_new((SSL_CTX*)tls_ctx);
    if (tls == 0) {
        ERR_print_errors_cb(print_errors, 0);
    }
    if (SSL_set_fd(tls, fd) == 0) {
        ERR_print_errors_cb(print_errors, 0);
        SSL_free(tls);
        return 0;
    }
    SSL_set_accept_state(tls);
    return tls;
}

void free_tls(void* tls) {
    if (tls != 0) {
        SSL_free((SSL*)tls);
    }
}

enum recv_tls_result recv_tls(void* tls, char* buf, int buf_len, int* num_bytes_read) {
    *num_bytes_read = SSL_read(tls, buf, buf_len);
    if (*num_bytes_read <= 0) {
        int err = SSL_get_error(tls, *num_bytes_read);
        *num_bytes_read = 0;
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_NONE) {
            return recv_tls_retry;
        }
        if (err == SSL_ERROR_ZERO_RETURN) {
            return recv_tls_eof;
        }
        ERR_print_errors_cb(print_errors, 0);
        return recv_tls_error;
    }
    return recv_tls_ok;
}

int write_tls(void* tls, const char* buf, int buf_len) {
    int r = SSL_write(tls, buf, buf_len);
    if (r <= 0) {
        int err = SSL_get_error(tls, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0;
        }
        ERR_print_errors_cb(print_errors, 0);
        return -1;
    }
    return r;
}
