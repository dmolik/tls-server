# TLS Server

This codebase is currently an experiment in writing a simple TLS server, using OpenSSL, pThreads, and Epoll.

## Building the TLS Server

### Requirements

OpenSSL-Headers (openssl-dev), make, lex (flex), yacc (bison), and a C compiler.

### Compiling

    make

or

    PERF=1 make

The ladder turning on some serious code optimizations.
