libssl:
	gcc ssl_server_libssl.c -o server -lssl -lcrypto
	gcc ssl_client_libssl.c -o client -lssl -lcrypto
clean:
	rm -rf server client
	

