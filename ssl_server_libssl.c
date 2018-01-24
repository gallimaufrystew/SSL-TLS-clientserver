#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h>
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/un.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
    #include "openssl\applink.c"
#endif

#ifdef _WIN32
#define sock_close closesocket
#endif

#ifdef _WIN32
    #pragma comment(lib,"ws2_32.lib")
    #pragma comment(lib,"libsslMDd.lib")
    #pragma comment(lib,"libcryptoMDd.lib")
#endif

#define TRUE   1
#define FALSE  0

#define CUSTOM_EXT_TYPE_1000 10000

static SSL_CTX *ssl_new_ctx;

SSL_CTX *create_ssl_ctx(const char *);
X509 *load_cert(const char *file);

static int cert_callback(SSL *ssl, void *a);
static int ana_ext_callback(SSL *ssl, unsigned int ext_type,const unsigned char *in,
                            size_t inlen, int *al, void *arg);

int main()
{
    int verify_peer = TRUE;
    int fd;
    struct sockaddr_in addr;
    SSL *ssl = NULL;
    SSL_CTX *ssl_ctx;
    
    
    SSL_library_init();
    SSL_load_error_strings();

#ifdef _WIN32
    WSADATA  ws_data;
    if (WSAStartup(MAKEWORD(2, 2), &ws_data)) {
        fprintf(stderr, "WSAStartup() fail: %d\n", GetLastError());
        return -1;
    }
#endif

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);/* inet_addr("127.0.0.1") */

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind() failed");
        exit(EXIT_FAILURE);
    }

    if (listen(fd, 16) < 0) {
        perror("listen() failed");
        exit(EXIT_FAILURE);
    }

    ssl_ctx = create_ssl_ctx("sha1");
    ssl_new_ctx = create_ssl_ctx("sha2");
    
    for ( ;; ) {
        
		char buf[1024] = {0};
        int rsize = 0,alen,ret;
        int client;

        client = accept(fd, NULL, 0);
        
        ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            printf("SSL_new() fail\n");
            return -1;
        }
        SSL_set_fd(ssl, client);

#if (0)        
        SSL_set_cert_cb(ssl, cert_callback, NULL); 
#endif
        
        if ((ret = SSL_accept(ssl)) != 1) {

            ERR_print_errors_fp(stderr);
            sock_close(client);
            SSL_free(ssl);
            continue;
        }

        if (verify_peer) {
            X509 *cert = SSL_get_peer_certificate(ssl);
            if (cert) {
                long ret = SSL_get_verify_result(ssl);
                if (ret != X509_V_OK) {
                    ERR_print_errors_fp(stderr);
                    printf("verify client failed\n");
                } else {
                    printf("verify client ok\n");
                }
                X509_free(cert);
            } else {
                printf("no peer certificate\n");
            }
        }
        
        rsize = SSL_read(ssl, buf, sizeof(buf));
        
        printf("received [%d][%s]\n",rsize,buf);
        
        alen = strlen("::Appended by SSL server::");
        strcat(buf,"::Appended by SSL server::");

        SSL_write(ssl, buf, rsize + alen + 1);

        SSL_shutdown(ssl);
        sock_close(client);
        SSL_free(ssl);
    }

    SSL_CTX_free(ssl_ctx);
    SSL_CTX_free(ssl_new_ctx);

    sock_close(fd);

#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
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

static int svr_name_callback(SSL *ssl, int *a, void *b)
{
    if (!ssl) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    const char *svrname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!svrname || svrname[0] == '\0') {
        return SSL_TLSEXT_ERR_NOACK;
    }

    /* loading certificate based on sni */
    printf("svrname:%s\n", svrname);

    return SSL_TLSEXT_ERR_OK;
}

SSL_CTX *create_ssl_ctx(const char *sign_algo)
{
    SSL_CTX *ssl_ctx = NULL;
    char file_name[512] = {0};
    
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_add_server_custom_ext(ssl_ctx, CUSTOM_EXT_TYPE_1000,
                                  NULL,
                                  NULL, NULL,
                                  ana_ext_callback, NULL);

    sprintf(file_name, "server_%s.crt", sign_algo);

#if (1)
    //SSL_CTX_use_certificate_chain_file
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

    sprintf(file_name, "server_%s.key", sign_algo);
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
    
    
#if (1)
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    // we can string certs together to form a cert-chain
    sprintf(file_name, "ca_%s.crt", sign_algo);
    if (!SSL_CTX_load_verify_locations(ssl_ctx, file_name, NULL)) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    //SSL_CTX_set_verify_depth(ssl_ctx, 1);
    //SSL_CTX_set_tlsext_servername_callback(ssl_ctx, svr_name_callback);
#endif
    
    return ssl_ctx;
}

static int ana_ext_callback(SSL *ssl, unsigned int ext_type,
                            const unsigned char *in,size_t inlen, int *al, void *arg)
{
	char ext_buf[2048] = {0};
	char *tag = NULL;
    char cust_tag[1024] = {0};
    
	memcpy(ext_buf, in, inlen);
	
	printf("---ext parse callback---\n");

	tag = strstr(ext_buf,"sign_algo=");
	if (tag) {
		sprintf(cust_tag,"%s",tag + strlen("sign_algo="));
	}

	printf("---cert tag [%s]----\n",cust_tag);
    
    SSL_set_SSL_CTX(ssl,ssl_new_ctx);

    return 1;
}

static int cert_callback(SSL *ssl, void *a)
{

    printf("------certificate callback %p-------\n",ssl_new_ctx);

    //SSL_set_SSL_CTX(ssl, ssl_new_ctx);

#if (0)    
    SSL_set_verify(ssl,SSL_CTX_get_verify_mode(ssl_new_ctx),
                 SSL_CTX_get_verify_callback(ssl_new_ctx));
    
    SSL_set_options(ssl,SSL_CTX_get_options(ssl_new_ctx));
#endif
    
    return 1;
}
