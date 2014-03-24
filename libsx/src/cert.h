#ifndef CERT_H
#define CERT_H

#include <curl/curl.h>
#include <openssl/x509.h>
#include "libsx-int.h"
CURLcode sxi_verifyhost(sxc_client_t *sx, const char *hostname, X509 *server_cert);
#endif
