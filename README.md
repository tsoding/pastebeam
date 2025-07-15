# PasteBEAM

TCP-only pastebin-like service with Proof-of-Work.

## Quick Start

### Server

```console
$ erl
> c(pastebeam).
> pastebeam:start().
```

### Client

#### Get

```
$ telnet <host> <port>
> GET <id>
```

#### Post

```
$ ./post.py <host> <port> <file-path>
```
