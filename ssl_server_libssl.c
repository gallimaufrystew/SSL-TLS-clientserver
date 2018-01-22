#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
/* #include <sys/un.h> */
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SSL_SERVER_RSA_CERT	"/home/labia/certs/cacert/server.crt"
#define SSL_SERVER_RSA_KEY	"/home/labia/certs/server.key"
#define SSL_SERVER_RSA_CA_CERT	"/home/labia/certs/ca.crt"
#define SSL_SERVER_RSA_CA_PATH	"/home/labia/certs/"

#define OFF	0
#define ON	1

#define CUSTOM_EXT_TYPE_1000 1000

static SSL_CTX *ssl_ctx,*new_ssl_ctx;

static int custom_ext_parse_callback(SSL *s, unsigned int ext_type,
                                     const unsigned char *in,
                                     size_t inlen, int *al, void *arg)
{
    char cert_tag[1024] = {0};
	char ext_buf[2048] = {0};

	memcpy(ext_buf, in, inlen);
	
	printf("---------custom extension parse callback-------\n");
	
	char *tag = nullptr;
	tag = strstr(ext_buf,"algo=");
	if (tag) {
		sprintf(cert_tag,"%s",tag + strlen("algo="));
	}

	printf("----------cert tag %s-----------------\n",cert_tag);

    new_ssl_ctx = create_ssl_ctx(cert_tag);

    SSL_set_SSL_CTX(s,new_ssl_ctx);

    return 1;
}

X509 *load_cert(const char *file)
{
    X509   *x = nullptr;
    BIO    *err = nullptr, *cert = nullptr;

    cert = BIO_new(BIO_s_file());
    if (cert == nullptr) {
        ERR_print_errors(err);
        goto end;
    }

    if (BIO_read_filename(cert, file) <= 0) {
        BIO_printf(err, "Error opening %s\n", file);
        ERR_print_errors(err);
        goto end;
    }

    x = PEM_read_bio_X509_AUX(cert, nullptr, nullptr, nullptr);

end:
    if (x == nullptr) {
        BIO_printf(err, "unable to load certificate\n");
        ERR_print_errors(err);
    }
    if (cert != nullptr) {
        BIO_free(cert);
    }
    return (x);
}

SSL_CTX *create_ssl_ctx(const char *sign_algo)
{
    SSL_CTX *ssl_ctx = nullptr;
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    SSL_CTX_add_server_custom_ext(ssl_ctx, CUSTOM_EXT_TYPE_1000,
                                  nullptr,/*svr_custom_ext_add_cb,*/
                                  nullptr, nullptr,
                                  svr_custom_ext_parse_cb, nullptr);

    char file_name[512] = {0};
    sprintf(file_name, "server_%s.crt", sign_algo);

#if (0)
    if (SSL_CTX_use_certificate_file(ssl_ctx, file_name, SSL_FILETYPE_PEM) <= 0) {
        //printf("SSL_CTX_use_certificate_file() fail");
        ERR_print_errors_fp(stderr);
        return -1;
    }
#else
    X509 *x509 = load_cert(file_name);

    if (SSL_CTX_use_certificate(ssl_ctx, x509) <= 0) {
        //printf("SSL_CTX_use_certificate_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    X509_free(x509);
#endif

    sprintf(file_name, "server_%s.key", sign_algo);
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, file_name, SSL_FILETYPE_PEM) <= 0) {
        //printf("SSL_CTX_use_PrivateKey_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        //printf("Private and certificate is not matching\n");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    
    sprintf(file_name, "c_ca_%s.crt", sign_algo);
    if (!SSL_CTX_load_verify_locations(ssl_ctx, file_name, nullptr)) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    /* SSL_CTX_set_tlsext_servername_callback(ssl_ctx, svr_name_callback); */

    return ssl_ctx;
}

int main()
{
	int verify_peer = OFF;
	/* SSL_METHOD *server_meth; */
	SSL_CTX *ssl_server_ctx;
	int serversocketfd;
	int clientsocketfd;
	/* struct sockaddr_un serveraddr; */
	int handshakestatus;

	SSL_library_init();
	SSL_load_error_strings();
    
    ssl_server_ctx = create_ssl_ctx("sha1");
    
/* server_meth = SSLv3_server_method(); 
	ssl_server_ctx = SSL_CTX_new(SSLv3_server_method());
	if(!ssl_server_ctx)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if(SSL_CTX_use_certificate_file(ssl_server_ctx, SSL_SERVER_RSA_CERT, SSL_FILETYPE_PEM) <= 0)	
	{
		ERR_print_errors_fp(stderr);
		return -1;		
	}

	if(SSL_CTX_use_PrivateKey_file(ssl_server_ctx, SSL_SERVER_RSA_KEY, SSL_FILETYPE_PEM) <= 0)	
	{
		ERR_print_errors_fp(stderr);
		return -1;		
	}
	
	if(SSL_CTX_check_private_key(ssl_server_ctx) != 1)
	{
		printf("Private and certificate is not matching\n");
		return -1;
	}	
*/
    
	if(verify_peer)
	{	
		//See function man pages for instructions on generating CERT files
		if(!SSL_CTX_load_verify_locations(ssl_server_ctx, SSL_SERVER_RSA_CA_CERT, NULL))
		{
			ERR_print_errors_fp(stderr);
			return -1;		
		}
		SSL_CTX_set_verify(ssl_server_ctx, SSL_VERIFY_PEER, NULL);
	}

    if ((serversocketfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("socket fail\n");
        return -1;
    }

#ifndef WIN32
    int reuse = 1;
    setsockopt(serversocketfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int));
#endif

    memset(&serveraddr, 0, sizeof(struct sockaddr_in));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(443);
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    
	if(bind(serversocketfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_in)))
	{
		printf("server bind error\n");
		return -1;
	}
	
	if(listen(serversocketfd, 5))
	{
		printf("Error on listen\n");
		return -1;
	}
    
	while (1)
	{
		SSL *serverssl;
		char buffer[1024];
		int bytesread = 0;
		int addedstrlen;
		int ret;
	
		clientsocketfd = accept(serversocketfd, NULL, 0);
		serverssl = SSL_new(ssl_server_ctx);
		if(!serverssl)
		{
			printf("Error SSL_new\n");
			return -1;
		}
		SSL_set_fd(serverssl, clientsocketfd);
		
		if((ret = SSL_accept(serverssl)) != 1)
		{
			printf("Handshake Error %d\n", SSL_get_error(serverssl, ret));
			return -1;
		}
		
		if(verify_peer)
		{
			X509 *ssl_client_cert = NULL;
			ssl_client_cert = SSL_get_peer_certificate(serverssl);
			if(ssl_client_cert)
			{
				long ret = SSL_get_verify_result(serverssl);
				if(verifyresult != X509_V_OK)
					printf("Certificate Verify Failed\n"); 
				X509_free(ssl_client_cert);
			}
		}
        
		bytesread = SSL_read(serverssl, buffer, sizeof(buffer));
		addedstrlen = strlen("Appended by SSL server");
		strncpy(&buffer[bytesread], "Appended by SSL server", addedstrlen);
		buffer[bytesread +  addedstrlen ] = '\0';
		SSL_write(serverssl, buffer, bytesread + addedstrlen + 1);
		SSL_shutdown(serverssl);
		close(clientsocketfd);
		SSL_free(serverssl);
	}
    
	close(serversocketfd);
	SSL_CTX_free(ssl_server_ctx);
    
	return 0;	
}
