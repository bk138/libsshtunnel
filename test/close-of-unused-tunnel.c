/*
  This tests closing of a tunnel that has not been used.
*/

#include <stdlib.h>
#include <assert.h>
#include "libsshtunnel.h"

int ssh_fingerprint_check(void* client,
			  const char *fingerprint,
			  int fingerprint_len,
                          const char *host) {
    return 0;
}


int main() {
    assert(ssh_tunnel_init() == 0);

    ssh_tunnel_t *t = ssh_tunnel_open_with_password(getenv("LIBSSHTUNNEL_TEST_SSH_HOST"),
                                                    getenv("LIBSSHTUNNEL_TEST_SSH_USER"),
                                                    getenv("LIBSSHTUNNEL_TEST_SSH_PASSWORD"),
                                                    getenv("LIBSSHTUNNEL_TEST_REMOTE_HOST"),
                                                    atoi(getenv("LIBSSHTUNNEL_TEST_REMOTE_PORT")),
                                                    NULL,
                                                    ssh_fingerprint_check,
                                                    NULL);

    assert(t);

    ssh_tunnel_close(t);

    return EXIT_SUCCESS;
}
