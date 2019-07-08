# What is netmgr
netmgr (aka rainbow duck) is the new networking system for BIND. It's based on libuv, although it does not expose any of the libuv api - to keep the API agnostic of underlying library.
## A bit of history
Networking in BIND9 up to 9.12 works with a single event loop (epoll on Linux, kqueue on fbsd, etc).

When a client wants to read from a socket it creates a socketevent with a task that will receive this event. isc_socket_{read,write,etc.} operation tries to read directly from the socket, if it succeeds it sends the socketevent to the task provided by the callee. If it doesn't it adds an event to an event loop, and when this event is received the listener is re-set, and an internal task is launched to read the data from the socket. After the internal task is done it launches the task from socketevent provided by the callee. This means that a simple socket operation causes a lot of context switches.

9.14 fixed some of these issues by having multiple event loops in separate threads (one per CPU), that read the data immediately and then call the socketevent - which is still sub-optimal.

## Internals - event loops
Internally new 


## Basic concepts

### `isc_nm_t`

### `isc_nmsocket_t`
nmsocket is a wrapper around a libuv socket

### `isc_nmhandle_t`
nmhandle is an interface that can be read or written - for TCP it's just a socket, for UDP it's a socket with peer address. The idea is that he client should not care what the underlying transport is.

## UDP listening

## TCP listening

## TCP listening for DNS


