// SPDX-License-Identifier: GPL-2.0

/* Test kTLS
 *
 * Implements a simple TLS server
 * Optionally enable kernel TLS mode
 *
 * Requires openssl 1.0 (i.e., not 1.1+) for direct struct access
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/tcp.h>
#include <linux/tls.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

/* define some openssl internals */
#ifndef EVP_AES_GCM_CTX
typedef struct { uint64_t val[2]; } uint128_t;

struct gcm128_context {
	uint128_t Yi,EKi,EK0,len,Xi,H;
	uint128_t Htable[16];
	void *gmult;
	void *ghash;
	unsigned int mres, ares;
	void *block;
	void *key;
};

typedef struct {
	union {
		double align;	/* essential, see with pahole */
		AES_KEY ks;
	} ks;
	int key_set;
	int iv_set;
	GCM128_CONTEXT gcm;
	unsigned char *iv;
	int ivlen;
	int taglen;
	int iv_gen;
	int tls_aad_len;
	ctr128_f ctr;
} EVP_AES_GCM_CTX;
#endif

static bool cfg_do_ktls;

static void error_ssl(void)
{
	ERR_print_errors_fp(stderr);
	exit(1);
}

static int setup_tcp(void)
{
	struct sockaddr_in6 addr = {0};
	int fd, one = 1;

	fd = socket(PF_INET6, SOCK_STREAM, 0);
	if (fd == -1)
		error(1, errno, "socket");

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
		error(1, errno, "setsockopt reuseaddr");

	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(443);
	addr.sin6_addr = in6addr_any;
	if (bind(fd, (void *)&addr, sizeof(addr)))
		error(1, errno, "bind");

	if (listen(fd, 1))
		error(1, errno, "listen");

	return fd;
}

static SSL_CTX * setup_tls(void)
{
	SSL_CTX *ctx;

	SSL_library_init();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx)
		error_ssl();

	/* TODO: understand why no shared cipher failure in this mode */
	//if (SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256") != 1)
	if (SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256") != 1)
		error_ssl();

	if (SSL_CTX_use_certificate_file(ctx, "test.pem", SSL_FILETYPE_PEM) != 1)
		error_ssl();

	if (SSL_CTX_use_PrivateKey_file(ctx, "test.pem", SSL_FILETYPE_PEM) != 1)
		error_ssl();

	return ctx;
}

static void readwrite_tls(SSL *ssl)
{
	char msg;

	if (SSL_read(ssl, &msg, sizeof(msg)) != 1)
		error_ssl();

	printf("recv: %c (SSL_read)\n", msg);

	if (SSL_write(ssl, &msg, sizeof(msg)) != 1)
		error_ssl();

	printf("sent: %c (SSL_write)\n", msg);
}

static void setup_kernel_tls(SSL *ssl, int fd, bool is_tx)
{
	struct tls12_crypto_info_aes_gcm_128 ci = {0};
	struct ssl_st *_ssl = (void *) ssl;
	EVP_AES_GCM_CTX *ctx;
	unsigned char *seq;
	int optname;

	if (is_tx) {
		ctx = (void *) _ssl->enc_write_ctx->cipher_data;
		seq = _ssl->s3->write_sequence;
		optname = TLS_TX;
	} else {
		ctx = (void *) _ssl->enc_read_ctx->cipher_data;
		seq = _ssl->s3->read_sequence;
		optname = TLS_RX;
	}

	ci.info.version = TLS_1_2_VERSION;
	ci.info.cipher_type = TLS_CIPHER_AES_GCM_128;

	memcpy(ci.rec_seq, seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
	memcpy(ci.key, ctx->gcm.key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(ci.salt, ctx->iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memcpy(ci.iv, ctx->iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
	       TLS_CIPHER_AES_GCM_128_IV_SIZE);

	if (setsockopt(fd, SOL_TLS, optname, &ci, sizeof(ci)))
		error(1, errno, "setsockopt tls %cx", is_tx ? 't' : 'r');
}

static void readwrite_kernel_tls(SSL *ssl, int fd)
{
	char msg[100];
	int ret;

	if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls")))
		error(1, errno, "setsockopt upper layer protocol");

	setup_kernel_tls(ssl, fd, true);
	setup_kernel_tls(ssl, fd, false);

	ret = read(fd, &msg, sizeof(msg));
	if (ret == -1)
		error(1, errno, "read");
	if (ret == 0)
		error(1, 0, "read: EOF");

	printf("recv: %c (kTLS)\n", msg[0]);

	if (write(fd, &msg, ret) != ret)
		error(1, errno, "write");

	printf("sent: %c (kTLS)\n", msg[0]);
}

static void usage(const char *filepath)
{
	error(1, 0, "usage: %s [-k]\n", filepath);
}

static void parse_opts(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "k")) != -1) {
		switch (c) {
		case 'k':
			cfg_do_ktls = true;
			break;
		default:
			usage(argv[0]);
		}
	}
}

int main(int argc, char **argv)
{
	SSL_CTX *ctx;
	SSL *ssl;
	int fd, fd_listen;

	parse_opts(argc, argv);

	ctx = setup_tls();

	fd_listen = setup_tcp();
	fd = accept(fd_listen, NULL, 0);
	if (fd == -1)
		error(1, errno, "accept");

	ssl = SSL_new(ctx);
	if (!ssl)
		error_ssl();

	if (SSL_set_fd(ssl, fd) != 1)
		error_ssl();

	if (SSL_accept(ssl) != 1)
		error_ssl();

	if (cfg_do_ktls)
		readwrite_kernel_tls(ssl, fd);
	else
		readwrite_tls(ssl);

        SSL_free(ssl);

	if (close(fd))
		error(1, errno, "close connection");
	if (close(fd_listen))
		error(1, errno, "close listen");

	SSL_CTX_free(ctx);

	return 0;
}

