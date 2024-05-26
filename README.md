# PolarGo

PolarGo is a HTTPS MITM proxy that allows you to intercept HTTP(S) traffic and recreate a PCAP based off the intercepted traffic. 

Currently, the tool only supports pcap-over-ip in client mode. 

## Installation

```bash
git clone https://github.com/mosajjal/polargo
cd polargo
CGO_ENABLED=0 go build -o polargo
```

## Usage

```bash
$ ./polargo -h
Usage of ./polargo:
  -destination string
        destination pcap-over-ip address (default "127.0.0.1:1234")
  -listen string
        listen address (default ":9080")
```

Support for pcap-over-ip in server mode, custom CA certificate, debug mode, and more is coming soon.

