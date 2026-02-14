/*
 * Simple C library to let your networking app connect to a host running behind a SSH server.
 *
 * Copyright (c) Christian Beier <info@christianbeier.net>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSSHTUNNEL_H
#define LIBSSHTUNNEL_H

#ifdef __cplusplus
extern "C" {
#endif

#define LIBSSHTUNNEL_VERSION_MAJOR 0
#define LIBSSHTUNNEL_VERSION_MINOR 4
#define LIBSSHTUNNEL_VERSION_PATCH 0

/**
   Handle to an SSH tunnel.
 */
typedef struct _ssh_tunnel ssh_tunnel_t;

typedef enum {
    /// Memory allocation error.
    LIBSSHTUNNEL_ERROR_MEM,
    /// Network socket operation error.
    LIBSSHTUNNEL_ERROR_SOCKET,
    /// Remote host name could not be resolved to IP address.
    LIBSSHTUNNEL_ERROR_NAME_RESOLUTION,
    /// Could not connect to SSH server.
    LIBSSHTUNNEL_ERROR_SSH_CONNECT,
    /// Could not initialise SSH connection.
    LIBSSHTUNNEL_ERROR_SSH_INIT,
    /// Could not finalise SSH handshake.
    LIBSSHTUNNEL_ERROR_SSH_HANDSHAKE,
    /// SSH fingerprint check callback returned -1.
    LIBSSHTUNNEL_ERROR_SSH_FINGERPRINT_CHECK,
    /// SSH user authentication failed.
    LIBSSHTUNNEL_ERROR_SSH_AUTH,
    /// SSH worker thread creation failed.
    LIBSSHTUNNEL_ERROR_THREAD,
    /// SSH server could not connect to remote.
    LIBSSHTUNNEL_ERROR_DIRECT_TCP_IP,
    /// Some read/write error while communicating with the remote and/or the SSH server.
    LIBSSHTUNNEL_ERROR_READ_WRITE,
} ssh_tunnel_error_t ;



/**
   Signal an error for a particular SSH tunnel client.
   This is mostly for informative purposes as the connection through
   the tunnel will disconnect on tunnel collapse anyway.
   NB that this might get called on a different thread than the one that
   opened the tunnel.
   @param client Application pointer given in tunnel open.
   @param error_code One of \ref ssh_tunnel_error_t
   @param error_message Human-readable error message
*/
typedef void (*ssh_tunnel_signal_error_func_t)(void *client,
                                               ssh_tunnel_error_t error_code,
                                               const char *error_message);

/**
   Decide whether or not the SSH tunnel setup should continue
   based on the current host and its fingerprint.
   Business logic is up to the implementer in the using app, i.e.
   compare keys, ask user etc...
   @param client Application pointer given in tunnel open.
   @param fingerprint SHA256 fingerprint of \p host
   @param fingerprint_len Length in bytes of \p fingerprint
   @param host The SSH server whose fingerprint is presented.
   @param port The port of the SSH server whose fingerprint is presented.
   @return -1 if tunnel setup should be aborted
            0 if tunnel setup should continue
 */
typedef int (*ssh_tunnel_fingerprint_check_func_t)(void *client,
                                                   const char *fingerprint,
                                                   int fingerprint_len,
                                                   const char *host,
                                                   int port);


/**
   Initialise libsshtunnel crypto backend and, if on Windows, Winsock.
   This is not thread safe; you must make sure this function is not called concurrently.
   @return 0 on success.
 */
int ssh_tunnel_init();


/**
   Dig a use-once SSH tunnel to a remote host, authenticated by password.
   Once established, the tunnel entry will listen on localhost on the port
   indicated by \ref ssh_tunnel_get_port().
   @param ssh_host The SSH server host to connect to.
   @param ssh_port The SSH server host's port to connect to.
   @param ssh_user The SSH user to authenticate as.
   @param ssh_password The SSH user password to authenticate with.
   @param remote_host The remote host to connect to from the SSH server.
   @param remote_port The port of the remote host to connect to from the SSH server.
   @param client Application pointer that's given to the SSH fingerprint check and log callbacks.
   @param ssh_fingerprint_check_callback SSH fingerprint check callback.
   @param error_callback Callback to log errors. Can be NULL.
   @return An open SSH tunnel to \p remote_host via \p ssh_host, listening on localhost.
 */
ssh_tunnel_t* ssh_tunnel_open_with_password(const char *ssh_host,
                                            int ssh_port,
                                            const char *ssh_user,
                                            const char *ssh_password,
                                            const char *remote_host,
                                            int remote_port,
                                            void *client,
                                            ssh_tunnel_fingerprint_check_func_t ssh_fingerprint_check_callback,
                                            ssh_tunnel_signal_error_func_t error_callback);


/**
   Dig a use-once SSH tunnel to a remote host, authenticated by private key.
   Once established, the tunnel entry will listen on localhost on the port
   indicated by \ref ssh_tunnel_get_port().
   @param ssh_host The SSH server host to connect to.
   @param ssh_port The SSH server host's port to connect to.
   @param ssh_user The SSH user to authenticate as.
   @param ssh_priv_key The SSH private key to authenticate with.
   @param ssh_priv_key_len The length in bytes of SSH private key to authenticate with.
   @param ssh_priv_key_password The SSH private key password to authenticate with.
   @param remote_host The remote host to connect to from the SSH server.
   @param remote_port The port of the remote host to connect to from the SSH server.
   @param client Application pointer that's given to the SSH fingerprint check and log callbacks.
   @param ssh_fingerprint_check_callback SSH fingerprint check callback.
   @param error_callback Callback to log errors. Can be NULL.
   @return An open SSH tunnel to \p remote_host via \p ssh_host, listening on localhost.
 */
ssh_tunnel_t* ssh_tunnel_open_with_privkey(const char *ssh_host,
                                           int ssh_port,
                                           const char *ssh_user,
                                           const char *ssh_priv_key,
                                           int ssh_priv_key_len,
                                           const char *ssh_priv_key_password,
                                           const char *remote_host,
                                           int remote_port,
                                           void *client,
                                           ssh_tunnel_fingerprint_check_func_t ssh_fingerprint_check_callback,
                                           ssh_tunnel_signal_error_func_t error_callback);


/**
   Get the local port of an SSH tunnel. Once having been connected to,
   this will return 0 and the tunnel will not accept new connections.
   @return The local port to connect to or
           @c 0 if the tunnel has already been connected or
           @c -1 if the tunnel is invalid.
 */
int ssh_tunnel_get_port(ssh_tunnel_t *tunnel);


/**
   Close the given SSH tunnel and dispose of it.
 */
void ssh_tunnel_close(ssh_tunnel_t *tunnel);


/**
   Shutdown libsshtunnel crypto backend and, if on Windows, deregister WinSock.
 */
void ssh_tunnel_exit();

#ifdef __cplusplus
}
#endif

#endif
