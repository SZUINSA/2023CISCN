dan# 2023CISCN

## RUN IN DOCKER

```bash
docker-compose up --scale services=X --scale port=Y --scale scan=Z -d
```

## FUNCTION

`--mysql` use mysql
default is sqlite

`--scan` scan the ip which is alive,  default it uses nmap

`--scan scan-fscan`, use fscan which is faster than the default one


`--port` find the open port from an ip, default it uses nmap

`--port port-allscan`, use nmap to scan 1-65535 port, it takes lots of time so be careful when using

`--port port-fscan`, use fscan which is faster than the default one


`--services` find the web service fingerprint, protocol and more information on certain ip

`--SERVICES services-fscan-protocol` Using fscan to identify the protocols used by the corresponding IP addresses, it is worth noting that, due to the characteristics of fscan itself, in order to save resources and improve efficiency, we have saved the web application detection by fscan during port scanning


`--honeypot` 木大你来写吧

`--scale` 木大好像在玩一种很新的东西，弟弟看不懂了


