# tlsc

A command line app to show TLS certificates for any HTTPS website

## Usage

```
tlsc [https://]<host or IP>[:port]
```

### Examples

**Inspect a domain name:**
```
tlsc www.example.com
```

**Inspect a domain name with non-standard port:**
```
tlsc www.example.com:7443
```

**Inspect an IPv4 address:**
```
tlsc 192.0.2.1
```

**Inspect an IPv6 address:**
```
tlsc [2001:db8::1]
```


That's it.

## Todo:

- [x] Support custom port numbers
- [ ] Support specifying ciphersuite
- [ ] Support specifying TLS version
