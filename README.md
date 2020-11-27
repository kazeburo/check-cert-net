# check-cert-net

Check a remote certification expiry using openssl s_client.

## Usage

```
% ./check-cert-net -h
Usage:
  check-cert-net [OPTIONS]

Application Options:
  -H, --host=       Hostname (default: localhost)
  -p, --port=       Port (default: 443)
      --servername= servername in ClientHello
      --timeout=    Timeout to connect mysql (default: 5s)
      --rsa         Preferred aRSA cipher to use
      --ecdsa       Preferred aECDSA cipher to use
  -c, --critical=   The critical threshold in days before expiry (default: 14)
  -w, --warning=    The threshold in days before expiry (default: 30)

Help Options:
  -h, --help        Show this help message
```

```
$ check-cert-net --servername example.com --host 127.0.0.1 --port 443 --rsa -w 10 -c 7
check-cert-net OK: Expiration date: 2020-07-02, 62 days remaining
```

## Install

```
$ mkr plugin install kazeburo/check-cert-net
```

