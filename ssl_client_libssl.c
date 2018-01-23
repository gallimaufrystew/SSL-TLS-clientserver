#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define TRUE   1
#define FALSE  0

#define CUSTOM_EXT_TYPE_1000 10000

const char cust_str[] = "sign_algo=sha2";

X509 *load_cert(const char *file);
SSL_CTX *create_ssl_ctx(const char *sign_algo);
static int add_cust_ext_callback(SSL *s, unsigned int ext_type,
                                 const unsigned char **out,
                                 size_t *outlen, int *al, void *arg);
int main()
{
    int verify_peer = TRUE;
    SSL_CTX *ssl_ctx;
    int fd;
    struct sockaddr_in addr;

    SSL *ssl;
    char buffer[1024] = "Client Hello World";
    int ret;
    
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ssl_ctx = create_ssl_ctx("sha2");
    if (!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_CTX_add_server_custom_ext(ssl_ctx, CUSTOM_EXT_TYPE_1000,
                                  add_cust_ext_callback,
                                  NULL, NULL,NULL, NULL);

    if ((fd = socket(/* AF_UNIX */AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Error on socket creation\n");
        return -1;
    }

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = INADDR_ANY;//inet_addr("10.123.162.58");/*  */

    connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        printf("Error SSL_new\n");
        return -1;
    }
    SSL_set_fd(ssl, fd);

    if ((ret = SSL_connect(ssl)) != 1) {
        ERR_print_errors_fp(stderr);
        printf("Handshake Error %d\n", SSL_get_error(ssl, ret));
        return -1;
    }

    if (verify_peer) {
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            long ret = SSL_get_verify_result(ssl);
            if (ret != X509_V_OK) {
                printf("verify failed\n");
                goto fail;
            } else {
                printf("verify ok\n");
            }
            X509_free(cert);
        } else {
            printf("no peer certificate\n");
        }
    }
    
    SSL_write(ssl, buf, strlen(buf) + 1);
    SSL_read(ssl, buf, sizeof(buf));
    printf("SSL server send [%s]\n", buf);
    
fail:    
    SSL_shutdown(ssl);
    close(fd);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);

    return 0;
}

static int add_cust_ext_callback(SSL *s, unsigned int ext_type,
                                 const unsigned char **out,
                                 size_t *outlen, int *al, void *arg)
{
    
    printf("-----add cust ext-----\n");
    
    *out = (const unsigned char *)cust_str;
    *outlen = strlen(cust_str);

    return 1;
}

X509 *load_cert(const char *file)
{
    X509   *x = NULL;
    BIO    *err = NULL, *cert = NULL;

    cert = BIO_new(BIO_s_file());
    if (cert == NULL) {
        ERR_print_errors(err);
        goto end;
    }

    if (BIO_read_filename(cert, file) <= 0) {
        BIO_printf(err, "Error opening %s\n", file);
        ERR_print_errors(err);
        goto end;
    }

    x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);

end:
    if (x == NULL) {
        BIO_printf(err, "unable to load certificate\n");
        ERR_print_errors(err);
    }
    if (cert != NULL) {
        BIO_free(cert);
    }
    return (x);
}

SSL_CTX *create_ssl_ctx(const char *sign_algo)
{
    SSL_CTX *ssl_ctx = NULL;
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_add_client_custom_ext(ssl_ctx, CUSTOM_EXT_TYPE_1000,
                                  add_cust_ext_callback,
                                  NULL, NULL,
                                  NULL, NULL);

    char file_name[512] = {0};
    sprintf(file_name, "client_%s.crt", sign_algo);

#if (1)
    //SSL_CTX_use_certificate_file SSL_FILETYPE_PEM
    if (SSL_CTX_use_certificate_file(ssl_ctx, file_name,SSL_FILETYPE_PEM) <= 0) {
        //printf("SSL_CTX_use_certificate_file() fail");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
#else
    X509 *x509 = load_cert(file_name);

    if (SSL_CTX_use_certificate(ssl_ctx, x509) <= 0) {
        //printf("SSL_CTX_use_certificate_file() fail");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    X509_free(x509);
#endif

    sprintf(file_name, "client_%s.key", sign_algo);
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, file_name, SSL_FILETYPE_PEM) <= 0) {
        //printf("SSL_CTX_use_PrivateKey_file() fail");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        //printf("Private and certificate is not matching\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // we can string certs together to form a cert-chain
    sprintf(file_name, "ca_%s.crt", sign_algo);
    if (!SSL_CTX_load_verify_locations(ssl_ctx, file_name, NULL)) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    //SSL_CTX_set_verify_depth(ssl_ctx, 1);
    //SSL_CTX_set_tlsext_servername_callback(ssl_ctx, svr_name_callback);

    return ssl_ctx;
}
