# 2023CISCN

## 用Linux系统作测试

```bash
docker build -t cicsn .
#在运行前先将dockerfile先build了
docker-compose up -d
#你可以更改其中的replicas参数来启用多个容器实现并发扫描
```

## 命令

```bash
python main.py <OPTIONS>
#运行指令
python json.py <FILENAME>
#导出文件，FILENAME为导出文件名，默认为output.json
```
OPTIONS有如下：

`--mysql` 使用MYSQL模块（支持分布式），默认使用为SQLITE模块（不支持分布式）

`--scan` 使用默认探活工具NAMP

`--scan scan-fscan`, 使用探活工具FSCAN

`--port` 使用默认端口扫描工具NMAP

`--port port-allscan`, 使用NMAP进行全端口扫描

`--port port-fscan`, 使用FSCAN进行端口扫描

`--port port-fofa`, 使用FOFA进行端口扫描

`--port port-quake`, 使用QUAKE进行端口扫描

`--services` 使用默认工具KSCAN进行端口/协议/服务探测

`--services services-fscan-protocol` 使用FSCAN进行协议探测，前提是以及执行过FSCAN端口探测

`--honeypot` 使用默认的工具QUAKE识别蜜罐

`--honeypot fofa` 使用FOFA识别蜜罐

`--honeypot quake-dump` 使用QUAKE的DUMP数据识别蜜罐

`--scale` 如果你在并发执行，请在命令中加入该选项以随机启动时间


