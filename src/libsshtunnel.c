/*
 * Copyright (c) Christian Beier <info@christianbeier.net>
 * Copyright (c) The libssh2 project and its contributors for the parts from https://www.libssh2.org/examples/direct_tcpip.html
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This library is based on https://www.libssh2.org/examples/direct_tcpip.html
 * with the following changes:
 *  - the listening is split out into a separate thread function
 *  - the listener gets closed immediately once a connection was accepted
 *  - the listening port is chosen by the OS, SO_REUSEADDR removed
 *  - global variables moved into _ssh_tunnel struct
 *  - name resolution added for the ssh host
 */


#include <libsshtunnel.h>
#include <libssh2.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#ifdef WIN32
#include <ws2tcpip.h>
#ifdef _MSC_VER
// Prevent POSIX deprecation warnings
#define strdup _strdup
// Use strerror_s for strerror_r
#define strerror_r(errno,buf,len) strerror_s(buf,len,errno)
#endif
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#if HAVE_THREADS_H
#include <threads.h>
#else
#include "c11threads.h"
#endif

/*
  Winsock vs BSD-sockets helper defines.
*/
#ifdef WIN32
#define LIBSSHTUNNEL_INVALID_SOCKET INVALID_SOCKET
#define _libsshtunnel_socket_close closesocket
#else
#define LIBSSHTUNNEL_INVALID_SOCKET (-1)
#define _libsshtunnel_socket_close close
#endif
/// A socket close wrapper that sets the socket to invalid after close.
#define libsshtunnel_socket_close(s)		\
    {						\
	if (s != LIBSSHTUNNEL_INVALID_SOCKET) {	\
	    _libsshtunnel_socket_close(s);	\
	    s = LIBSSHTUNNEL_INVALID_SOCKET;	\
	}					\
    }

#define LIBSSHTUNNEL_ERROR_MSG_LEN 128
#define LIBSSHTUNNEL_STRERROR_LEN LIBSSHTUNNEL_ERROR_MSG_LEN/2

struct _ssh_tunnel {
    void *client;
    LIBSSH2_SESSION *session;
    int close_session;
    thrd_t thread;
    libssh2_socket_t ssh_sock;
    libssh2_socket_t local_listensock;
    int local_listenport;
    char *remote_desthost;
    int remote_destport;
    ssh_tunnel_signal_error_func_t signal_error_callback;
};


static int ssh_conveyor_loop(void *arg) {
    ssh_tunnel_t *data = arg;
    int rc;
    struct sockaddr_in sin;
    socklen_t sinlen = sizeof(sin);
    LIBSSH2_CHANNEL *channel = NULL;
    const char *shost;
    int sport;
    fd_set fds;
    struct timeval tv;
    ssize_t len, wr;
    char buf[16384];
    libssh2_socket_t proxy_sock = LIBSSHTUNNEL_INVALID_SOCKET;

    proxy_sock = accept(data->local_listensock, (struct sockaddr *)&sin, &sinlen);
    if(proxy_sock == LIBSSHTUNNEL_INVALID_SOCKET) {
	if(data->signal_error_callback) {
	    char err_str[LIBSSHTUNNEL_STRERROR_LEN];
	    strerror_r(errno, err_str, LIBSSHTUNNEL_STRERROR_LEN);
	    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
	    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_conveyor_loop: accept: %s\n", err_str);
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_SOCKET, msg);
	}
        goto shutdown;
    }

    /* Close listener once a connection got accepted */
    libsshtunnel_socket_close(data->local_listensock);
    data->local_listenport = 0;

    shost = inet_ntoa(sin.sin_addr);
    sport = ntohs(sin.sin_port);

    channel = libssh2_channel_direct_tcpip_ex(data->session, data->remote_desthost,
        data->remote_destport, shost, sport);
    if(!channel) {
	if(data->signal_error_callback) {
	    data->signal_error_callback(data->client,
					LIBSSHTUNNEL_ERROR_DIRECT_TCP_IP,
					"ssh_conveyor_loop: Could not open the direct-tcpip channel!\n"
					"(Note that this can be a problem at the server!"
					" Please review the server logs.)\n");
	}
        goto shutdown;
    }

    /* Must use non-blocking IO hereafter due to the current libssh2 API */
    libssh2_session_set_blocking(data->session, 0);

    while(!data->close_session) {
        FD_ZERO(&fds);
        FD_SET(proxy_sock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        rc = select((int)(proxy_sock + 1), &fds, NULL, NULL, &tv);
        if(-1 == rc) {
	    if(data->signal_error_callback) {
		char err_str[LIBSSHTUNNEL_STRERROR_LEN];
		strerror_r(errno, err_str, LIBSSHTUNNEL_STRERROR_LEN);
		char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
		snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_conveyor_loop: select: %s\n", err_str);
		data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_SOCKET, msg);
	    }
            goto shutdown;
        }
        if(rc && FD_ISSET(proxy_sock, &fds)) {
            len = recv(proxy_sock, buf, sizeof(buf), 0);
            if(len < 0) {
		if(data->signal_error_callback) {
		    char err_str[LIBSSHTUNNEL_STRERROR_LEN];
		    strerror_r(errno, err_str, LIBSSHTUNNEL_STRERROR_LEN);
		    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
		    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_conveyor_loop: read: %s\n", err_str);
		    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_READ_WRITE, msg);
		}
                goto shutdown;
            }
            else if(0 == len) {
		if(data->signal_error_callback) {
		    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
		    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_conveyor_loop: the client at %s:%d disconnected!\n", shost, sport);
		    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_READ_WRITE, msg);
		}
                goto shutdown;
            }
            wr = 0;
            while(wr < len) {
                ssize_t nwritten = libssh2_channel_write(channel, buf + wr, len - wr);
                if(LIBSSH2_ERROR_EAGAIN == nwritten) {
                    continue;
                }
                if(nwritten < 0) {
		    if(data->signal_error_callback) {
			char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
			snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_conveyor_loop: libssh2_channel_write: %ld\n", nwritten);
			data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_READ_WRITE, msg);
		    }
                    goto shutdown;
                }
                wr += nwritten;
            }
        }
        while(1) {
            len = libssh2_channel_read(channel, buf, sizeof(buf));
            if(LIBSSH2_ERROR_EAGAIN == len || data->close_session)
                break;
            else if(len < 0) {
		if(data->signal_error_callback) {
			char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
			snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_conveyor_loop: libssh2_channel_read: %d\n", (int)len);
			data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_READ_WRITE, msg);
		}
                goto shutdown;
            }
            wr = 0;
            while(wr < len) {
                ssize_t nsent = send(proxy_sock, buf + wr, len - wr, 0);
                if(nsent <= 0) {
		    if(data->signal_error_callback) {
			char err_str[LIBSSHTUNNEL_STRERROR_LEN];
			strerror_r(errno, err_str, LIBSSHTUNNEL_STRERROR_LEN);
			char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
			snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_conveyor_loop: write: %s\n", err_str);
			data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_READ_WRITE, msg);
		    }
		    goto shutdown;
                }
                wr += nsent;
            }
            if(libssh2_channel_eof(channel)) {
		if(data->signal_error_callback) {
			char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
			snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_conveyor_loop: the server at %s:%d disconnected!\n",
				 data->remote_desthost, data->remote_destport);
			data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_READ_WRITE, msg);
		}
                goto shutdown;
            }
        }
    }

 shutdown:

    libsshtunnel_socket_close(proxy_sock);

    if(channel)
        libssh2_channel_free(channel);

    libssh2_session_disconnect(data->session, "Client disconnecting normally");
    libssh2_session_free(data->session);

    if(data->remote_desthost)
        free(data->remote_desthost);

    libsshtunnel_socket_close(data->ssh_sock);

    return 0;
}


int ssh_tunnel_init() {
    int rc;
#ifdef WIN32
    WSADATA wsadata;
    // positive on error as per https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
    rc = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if(rc) {
        return rc;
    }
#endif
    // negative on error as per https://libssh2.org/libssh2_init.html
    rc = libssh2_init(0);
    return rc;
}


void ssh_tunnel_exit() {
    libssh2_exit();
#ifdef WIN32
    WSACleanup();
#endif
}


static ssh_tunnel_t* ssh_tunnel_open(const char *ssh_host,
				     const char *ssh_user,
				     const char *ssh_password,
				     const char *ssh_priv_key,
				     int ssh_priv_key_len,
				     const char *ssh_priv_key_password,
				     const char *remote_host,
				     int remote_port,
				     void *client,
				     ssh_tunnel_fingerprint_check_func_t ssh_fingerprint_check_callback,
				     ssh_tunnel_signal_error_func_t signal_error_callback) {
    int rc;
    struct sockaddr_in sin;
    socklen_t sinlen;
    const char *fingerprint;
    char *userauthlist;
    struct addrinfo hints, *res;
    ssh_tunnel_t *data;

    /* Sanity checks */
    if(!ssh_host || !ssh_user || !remote_host) /* these must be set */
	return NULL;

    data = calloc(1, sizeof(ssh_tunnel_t));
    if(!data) {
	if(signal_error_callback) {
	    char err_str[LIBSSHTUNNEL_STRERROR_LEN];
	    strerror_r(errno, err_str, LIBSSHTUNNEL_STRERROR_LEN);
	    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
	    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_tunnel_open: could not allocate memory: %s\n", err_str);
	    signal_error_callback(client, LIBSSHTUNNEL_ERROR_MEM, msg);
	}
	return NULL;
    }

    // set the sockets to invalid so we don't close invalid sockets inadvertently
    data->local_listensock = data->ssh_sock = LIBSSHTUNNEL_INVALID_SOCKET;

    data->client = client;
    data->remote_desthost = strdup(remote_host); /* resolved by the server */
    data->remote_destport = remote_port;
    data->signal_error_callback = signal_error_callback;

    /* Connect to SSH server */
    data->ssh_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(data->ssh_sock == LIBSSHTUNNEL_INVALID_SOCKET) {
	if(data->signal_error_callback) {
	    char err_str[LIBSSHTUNNEL_STRERROR_LEN];
	    strerror_r(errno, err_str, LIBSSHTUNNEL_STRERROR_LEN);
	    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
	    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_tunnel_open: socket: %s\n", err_str);
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_SOCKET, msg);
	}
        goto error;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((rc = getaddrinfo(ssh_host, NULL, &hints, &res)) == 0) {
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = (((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr);
	freeaddrinfo(res);
    } else {
	if(data->signal_error_callback) {
	    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
	    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_tunnel_open: getaddrinfo: %s\n", gai_strerror(rc));
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_NAME_RESOLUTION, msg);
	}
	goto error;
    }

    sin.sin_port = htons(22);
    if(connect(data->ssh_sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) {
	if(data->signal_error_callback) {
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_SSH_CONNECT, "ssh_tunnel_open: failed to connect to SSH server!\n");
	}
	goto error;
    }

    /* Create a session instance */
    data->session = libssh2_session_init();
    if(!data->session) {
	if(data->signal_error_callback) {
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_SSH_INIT, "ssh_tunnel_open: could not initialize SSH session!\n");
	}
	goto error;
    }

    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    rc = libssh2_session_handshake(data->session, data->ssh_sock);
    if(rc) {
	if(data->signal_error_callback) {
	    char *error_msg;
	    libssh2_session_last_error(data->session, &error_msg, NULL, 0);
	    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
	    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_tunnel_open: error when starting up SSH session: %d: %s\n", rc, error_msg);
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_SSH_HANDSHAKE, msg);
	}
        goto error;
    }

    /* At this point we havn't yet authenticated.  The first thing to do
     * is check the hostkey's fingerprint against our known hosts Your app
     * may have it hard coded, may go to a file, may present it to the
     * user, that's your call
     */
    fingerprint = libssh2_hostkey_hash(data->session, LIBSSH2_HOSTKEY_HASH_SHA256);
    if(ssh_fingerprint_check_callback(data->client, fingerprint, 32, ssh_host) == -1) {
	if(data->signal_error_callback) {
	    data->signal_error_callback(data->client,
					LIBSSHTUNNEL_ERROR_SSH_FINGERPRINT_CHECK,
					"ssh_tunnel_open: fingerprint check indicated tunnel setup stop\n");
	}
        goto error;
    }

    /* check what authentication methods are available */
    userauthlist = libssh2_userauth_list(data->session, ssh_user, (unsigned int)strlen(ssh_user));
    if(ssh_password && strstr(userauthlist, "password")) {
        if(libssh2_userauth_password(data->session, ssh_user, ssh_password)) {
	    if(data->signal_error_callback) {
		data->signal_error_callback(data->client,
					    LIBSSHTUNNEL_ERROR_SSH_AUTH,
					    "ssh_tunnel_open: authentication by password failed.\n");
	    }
            goto error;
        }
    }
    else if(ssh_priv_key && ssh_priv_key_password && strstr(userauthlist, "publickey")) {
        if(libssh2_userauth_publickey_frommemory(data->session,
                                                 ssh_user, strlen(ssh_user),
                                                 NULL, 0,
                                                 (const char*)ssh_priv_key, ssh_priv_key_len,
                                                 ssh_priv_key_password)) {
	    if(data->signal_error_callback) {
		data->signal_error_callback(data->client,
					    LIBSSHTUNNEL_ERROR_SSH_AUTH,
					    "ssh_tunnel_open: authentication by public key failed!\n");
	    }
            goto error;
        }
    }
    else {
	if(data->signal_error_callback) {
	    data->signal_error_callback(data->client,
					LIBSSHTUNNEL_ERROR_SSH_AUTH,
					"ssh_tunnel_open: no supported authentication methods found!\n");
	}
        goto error;
    }

    /* Create and bind the local listening socket */
    data->local_listensock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(data->local_listensock == LIBSSHTUNNEL_INVALID_SOCKET) {
	if(data->signal_error_callback) {
	    char err_str[LIBSSHTUNNEL_STRERROR_LEN];
	    strerror_r(errno, err_str, LIBSSHTUNNEL_STRERROR_LEN);
	    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
	    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_tunnel_open: socket: %s\n", err_str);
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_SOCKET, msg);
	}
	goto error;
    }
    sin.sin_family = AF_INET;
    sin.sin_port = htons(0); /* let the OS choose the port */
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    if(INADDR_NONE == sin.sin_addr.s_addr) {
	if(data->signal_error_callback) {
	    char err_str[LIBSSHTUNNEL_STRERROR_LEN];
	    strerror_r(errno, err_str, LIBSSHTUNNEL_STRERROR_LEN);
	    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
	    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_tunnel_open: inet_addr: %s\n", err_str);
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_SOCKET, msg);
	}
        goto error;
    }
    sinlen = sizeof(sin);
    if(-1 == bind(data->local_listensock, (struct sockaddr *)&sin, sinlen)) {
	if(data->signal_error_callback) {
	    char err_str[LIBSSHTUNNEL_STRERROR_LEN];
	    strerror_r(errno, err_str, LIBSSHTUNNEL_STRERROR_LEN);
	    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
	    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_tunnel_open: bind: %s\n", err_str);
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_SOCKET, msg);
	}
        goto error;
    }
    if(-1 == listen(data->local_listensock, 1)) {
	if(data->signal_error_callback) {
	    char err_str[LIBSSHTUNNEL_STRERROR_LEN];
	    strerror_r(errno, err_str, LIBSSHTUNNEL_STRERROR_LEN);
	    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
	    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_tunnel_open: listen: %s\n", err_str);
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_SOCKET, msg);
	}
        goto error;
    }

    /* get info back from OS */
    if (getsockname(data->local_listensock, (struct sockaddr *)&sin, &sinlen ) == -1){
	if(data->signal_error_callback) {
	    char err_str[LIBSSHTUNNEL_STRERROR_LEN];
	    strerror_r(errno, err_str, LIBSSHTUNNEL_STRERROR_LEN);
	    char msg[LIBSSHTUNNEL_ERROR_MSG_LEN];
	    snprintf(msg, LIBSSHTUNNEL_ERROR_MSG_LEN, "ssh_tunnel_open: getsockname: %s\n", err_str);
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_SOCKET, msg);
	}
	goto error;
    }

    data->local_listenport = ntohs(sin.sin_port);

    /* Create the conveyor thread */
    if (thrd_create(&data->thread, ssh_conveyor_loop, data) != thrd_success) {
	if(data->signal_error_callback) {
	    data->signal_error_callback(data->client, LIBSSHTUNNEL_ERROR_THREAD, "ssh_tunnel_open: proxy thread creation failed\n");
	}
	goto error;
    }

    return data;

 error:
    if (data->session) {
	libssh2_session_disconnect(data->session, "Error in SSH tunnel setup");
	libssh2_session_free(data->session);
    }
    if(data->remote_desthost)
        free(data->remote_desthost);

    libsshtunnel_socket_close(data->local_listensock);
    libsshtunnel_socket_close(data->ssh_sock);

    free(data);

    return NULL;
}


ssh_tunnel_t *ssh_tunnel_open_with_password( const char *ssh_host,
					     const char *ssh_user,
					     const char *ssh_password,
					     const char *remote_host,
					     int remote_port,
					     void *client,
					     ssh_tunnel_fingerprint_check_func_t ssh_fingerprint_check_callback,
					     ssh_tunnel_signal_error_func_t signal_error_callback) {
    return ssh_tunnel_open(ssh_host,
			   ssh_user,
			   ssh_password,
			   NULL,
			   0,
			   NULL,
			   remote_host,
			   remote_port,
			   client,
			   ssh_fingerprint_check_callback,
			   signal_error_callback);
}


ssh_tunnel_t *ssh_tunnel_open_with_privkey(const char *ssh_host,
					   const char *ssh_user,
					   const char *ssh_priv_key,
					   int ssh_priv_key_len,
					   const char *ssh_priv_key_password,
					   const char *remote_host,
					   int remote_port,
					   void *client,
					   ssh_tunnel_fingerprint_check_func_t ssh_fingerprint_check_callback,
					   ssh_tunnel_signal_error_func_t signal_error_callback) {
    return ssh_tunnel_open(ssh_host,
			   ssh_user,
			   NULL,
			   ssh_priv_key,
			   ssh_priv_key_len,
			   ssh_priv_key_password,
			   remote_host,
			   remote_port,
			   client,
			   ssh_fingerprint_check_callback,
			   signal_error_callback);
}


int ssh_tunnel_get_port(ssh_tunnel_t *tunnel) {
  if (tunnel) {
      return tunnel->local_listenport;
  }
  return -1;
}


void ssh_tunnel_close(ssh_tunnel_t *data) {
    if(!data)
	return;

    // signal end to thread
    data->close_session = 1;
    libssh2_session_disconnect(data->session, "Orderly close from ssh_tunnel_close()");

    /* the proxy thread does the internal cleanup as it can be
       ended due to external reasons */
    thrd_join(data->thread, NULL);

    free(data);
}
