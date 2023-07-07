# 2023CISCN

## RUN IN DOCKER

```bash
docker-compose up --scale services=X --scale port=Y --scale scan=Z -d
```

## FUNCTION

--mysql use mysql
default is sqlite

`--scan` scan the ip which is alive,  default it uses nmap

`--scan scan-fscan`, use fscan which is faster than the default one


`--port` find the open port from an ip, default it uses nmap

`--port port-xxxx`, use nmap to scan 1-65535 port, it takes lots of time so be careful when using

`--port port-fscan`, use fscan which is faster than the default one


`--services` find the web service fingerprint, protocol and more information on certain ip
