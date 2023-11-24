# 2. Focus on a small, minimal API instead of a full-blown one

Date: 2023-11-24

## Status

Accepted

## Context

While creating this library, centralising code residing in two applications, the API pattern that emerged was one like

- init() for getting the backend setup

- NULL|tunnel = open() for opening the tunnel
  - with callbacks using the client pointer provided in open
- port = get_port() for getting the actual port from the tunnel
- close(tunnel) for closing and disposing of the tunnel

- exit() for de-initing the backend

It was felt this has some drawbacks, namely:

1. There are 2 handles; tunnel (open/close) and client (callbacks).
2. The use-once semantics of the port are communicated through a getter.
3. The fail semantics with open() first return a NULL tunnel but later on they do have a non-NULL tunnel -> One case needs tunne close, the other not.

An alternative API scheme was sketched out, roughly in the form of:

- init() as above

- tunnel = create()
- -1|port = open(tunnel)
  - with callbacks using the tunnel pointer instead of client
- client = get_client(tunnel) for getting the client in the callbacks
- close(tunnel)
- destroy(tunnel)

- exit() as above

This improves on the disadvantages lined out above:

1. There now is 1 handle: tunnel.
2. There now is 1 port return value for 1 open() call, making the use-once semantics of the port a bit clearer.
3. If tunnel != NULL always call destroy() on it.
  
But, this also introduces new disadvantages:

1. Makes implementation a lot more complex as the API allows re-use of tunnel objects, we have to cater for this internally.
2. Blows up the API surface with additional functions that make enable non-goal use cases like tunnel re-use.

## Decision

Keep the original, minimal API, going with the small drawback of having 2 handles.

## Consequences

- The good: Less internal complexity, we can get to a first release sooner w/o overengineering.
- The ugly: two handles in the API: tunnel and client.

