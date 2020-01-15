#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <iostream>
#include <sstream>
#include <string>
#include <regex>
#include <unistd.h>

using namespace std;

#define CERTIFICATE_CHAIN_MAXIMUM 10
static X509 * certificateChain[CERTIFICATE_CHAIN_MAXIMUM];
static int numberOfCerts = 0;

#define SSL_CLEANUP if (web != NULL) { BIO_free_all(web); }; if (ctx != NULL) { SSL_CTX_free(ctx); };
#define FATAL_ERROR(__msg, __code) print_error(__msg); SSL_CLEANUP; exit(__code);

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx) {
    STACK_OF(X509) * certs = X509_STORE_CTX_get1_chain(x509_ctx);
    X509 * cert;
    int count = sk_X509_num(certs);
    numberOfCerts = count;
    if (count > CERTIFICATE_CHAIN_MAXIMUM) {
        cerr << "Server returned too many certificates";
        return 0;
    }
    for (int i = 0; i < count; i++) {
        if (i < CERTIFICATE_CHAIN_MAXIMUM) {
            cert = sk_X509_value(certs, i);
            if (cert != NULL) {
                certificateChain[i] = cert;
            }
        }
    }

    return preverify;
}

void print_warning(string message) {
    cerr << "\033[1;33mWarning: \033[0m" << message << "\n";
}

void print_error(string message) {
    cerr << "\033[0;31mError: \033[0m" << message << "\n";
}

int main(int argc, char *argv[]) {
    int uid = getuid();
    if (uid == 0) {
        print_warning("Running tlsc as root is dangerous");
    }

    string url;
    if (argc == 1) {
        cerr << "Usage " << argv[0] << " <URL[:PORT]>\n";
        exit(1);
    }

    url = string(argv[1]);
    if (url.rfind("http://", 0) == 0) {
        cerr << "A valid HTTPS URL or Domain Name is required.\n";
        exit(1);
    }
    if (url.rfind("https://", 0) == 0) {
        url = regex_replace(url, regex("https://"), "");
    }
    string host = url.substr(0, url.find("/"));
    int port = 443;

    for (int i = 0; i < CERTIFICATE_CHAIN_MAXIMUM; i++) {
        certificateChain[i] = NULL;
    }
    numberOfCerts = 0;

    OPENSSL_init_ssl(0, NULL);
    OPENSSL_init_crypto(0, NULL);
    ERR_load_SSL_strings();

    SSL_CTX * ctx = NULL;
    BIO * web = NULL;
    SSL * ssl = NULL;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        FATAL_ERROR("Unsupported client method", 2);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_callback);
    SSL_CTX_set_verify_depth(ctx, CERTIFICATE_CHAIN_MAXIMUM);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    web = BIO_new_ssl_connect(ctx);
    if (web == NULL) {
        FATAL_ERROR("Connection setup failed", 3);
    }

    ostringstream connect;
    connect << url << ":" << port;
    if (BIO_set_conn_hostname(web, connect.str().c_str()) < 0) {
        FATAL_ERROR("Invalid hostname", 4);
    }

    BIO_get_ssl(web, &ssl);
    if (ssl == NULL) {
        FATAL_ERROR("SSL/TLS connection failure", 5);
    }

    const char * PREFERRED_CIPHERS = "HIGH:!aNULL:!MD5:!RC4";
    if (SSL_set_cipher_list(ssl, PREFERRED_CIPHERS) < 0) {
        FATAL_ERROR("Unsupported client ciphersuite", 6);
    }

    if (SSL_set_tlsext_host_name(ssl, host.c_str()) < 0) {
        FATAL_ERROR("Could not resolve hostname", 7);
    }

    if (BIO_do_connect(web) < 0) {
        FATAL_ERROR("Connection failed", 8);
    }

    if (BIO_do_handshake(web) < 0) {
        FATAL_ERROR("Connection failed", 9);
    }

    if (numberOfCerts > CERTIFICATE_CHAIN_MAXIMUM) {
        FATAL_ERROR("Too many certificates", 10);
    }

    if (numberOfCerts < 1) {
        FATAL_ERROR("No certificates returned", 11);
    }

    for (int i = 0; i < numberOfCerts; i++) {
        X509 * cert = certificateChain[i];
        X509_print_fp(stdout, cert);
    }

    SSL_CLEANUP
}
