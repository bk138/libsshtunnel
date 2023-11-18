
# libsshtunnel

libsshtunnel is a simple C library to let your networking app connect to a host running behind a SSH server.

## Example Usage

```
#include <libsshtunnel.h>

// Callback that handles the SSH server's fingerprint.
// For the example, acceps any fingerprint, but normally you would check against saved ones etc.
int ssh_fingerprint_check(const char *fingerprint, size_t fingerprint_len,
                          const char *host, void *client) {
    return 0;
}

// No extended error checking here for the sake of API showoff.
int main () {
	ssh_tunnel_init();
	ssh_tunnel_t *t = ssh_tunnel_open_with_password("ssh.server.net",       // Hostname of SSH server
                                                    "username",             // SSH user name
										            "password",             // SSH user's password
										            "localhost",            // Remote service is running directly on SSH server
										             26000,                 // Port of remote service
										             NULL,                  // FIXME
										             ssh_fingerprint_check, // SSH fingerprint check callback
										             NULL);	                // Callback for error reporting, can be omitted
	if(t) {
		// You can let your code connect to the local end of the tunnel,
		// your client will get connected to the server running on
		/ "ssh.server.net", port 26000.
		my_client_connect("localhost", ssh_tunnel_get_port(t));
	}
	
    return 0;	
}
```


