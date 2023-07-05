import nmap

target = "192.168.239.61"
nm = nmap.PortScanner()
nm.scan(hosts=target, arguments='-F')
for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)
        lport = nm[host][proto].keys()
        for port in lport:
            print(f'Port: {port}  State: {nm[host][proto][port]["state"]}')

# import nmap
#
# # 创建一个nmap.PortScanner对象
# scanner = nmap.PortScanner()
#
# # 执行扫描
# scanner.scan('192.168.239.61', '22-443')
#
# # 获取扫描结果
# for host in scanner.all_hosts():
#     print(f'Host: {host} ({scanner[host].hostname()})')
#     for proto in scanner[host].all_protocols():
#         print(f'Protocol: {proto}')
#         lport = scanner[host][proto].keys()
#         for port in lport:
#             print(f'Port: {port}  State: {scanner[host][proto][port]["state"]}')