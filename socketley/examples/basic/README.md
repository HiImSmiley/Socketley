# Basic Examples

These examples demonstrate the fundamental concepts of socketley.

## Prerequisites

Start the daemon before running any example:
```bash
socketley daemon &
```

## Examples

### 01 - Hello Server

Create and start a simple server listening on port 9000.

```bash
./01-hello-server.sh
```

### 02 - Hello Client

Create a client that connects to a server.

```bash
./02-hello-client.sh
```

### 03 - Combined

Complete server + client setup in one script.

```bash
./03-combined.sh
```

## Cleanup

```bash
socketley stop myserver myclient 2>/dev/null
socketley remove myserver myclient 2>/dev/null
```
