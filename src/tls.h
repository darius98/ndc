#ifndef NDC_TLS_H_
#define NDC_TLS_H_

void* init_tls(char* cert_pem_file);

void* new_tls_for_conn(void* tls_ctx, int fd);

void free_tls(void* tls);

int recv_tls(void* tls, char* buf, int buf_len);

int write_tls(void* tls, const char* buf, int buf_len);

#endif
