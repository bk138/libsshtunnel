[![CI](https://github.com/bk138/libsshtunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/bk138/libsshtunnel/actions/workflows/ci.yml)

# About

libsshtunnel is a simple SSH tunnel library to let your networking app connect to a host running behind a SSH server.

# Example Usage

```C
#include <libsshtunnel.h>

// Callback that handles the SSH server's fingerprint.
// For the example, accepts any fingerprint, but normally
// you would check against saved ones etc.
int ssh_fingerprint_check(void *client,
                          const char *fingerprint,
                          int fingerprint_len,
                          const char *host) {
    return 0;
}

// No extended error checking here for the sake of API showoff.
int main () {
    // Init crypto backend, has to be called only once.
    ssh_tunnel_init();

    // Open a tunnel. This one uses password auth, there also is a variant using the private key.
    ssh_tunnel_t *t = ssh_tunnel_open_with_password("ssh.server.net",       // Hostname of SSH server
                                                    "username",             // SSH user name
                                                    "password",             // SSH user's password
                                                    "localhost",            // Remote service is running directly on SSH server
                                                     26000,                 // Port of remote service
                                                     NULL,                  // You can give an application pointer here that's handed to the callbacks.
                                                     ssh_fingerprint_check, // SSH fingerprint check callback
                                                     NULL);                 // Callback for error reporting, can be omitted
    if(t) {
        // Initial tunnel creation succeeded; you can now let your code connect
        // to the local end of the tunnel:
        // Your client will get connected to the server running on
        // "ssh.server.net", port 26000, as specified above.
        my_client_connect("localhost", ssh_tunnel_get_port(t));

       // Your other logic here...
    }

    // Closes the tunnel and frees memory.
    ssh_tunnel_close(t);

    return 0;
}
```

# Building

libsshtunnel uses CMake, thus it's:

    mkdir build
    cd build
    cmake ..
    cmake --build .

# License

libsshtunnel is licensed under the BSD 3-Clause License.
See [COPYING](COPYING) for more information.
