# -*- coding: utf-8 -*-
import re
import os
import subprocess

def fscan_output_file(result, target):
    import os
    if os.name == 'nt':
        filepath = "tmp\\fscan\\"
    elif os.name == 'posix':
        filepath = "tmp/fscan/"
    if "/" in target:
        target = "result"
    with open(f'{filepath}fscan_{target.strip()}.txt', 'w') as f:
        f.write(result)

def Oslist(filepath,ip):
    if "/" in ip:
        ip = "result"
    with open(f'{filepath}fscan_{ip}.txt', 'r') as f:
        datalist = f.readlines()
    flag = 0
    for data in datalist:
        if "start vulscan" in data:
            flag = 1
        if flag:
            p = re.findall(r"\[\*\]\s(.*?)\:\s", data)
            if p:
                # print(p)
                # print(data)
                if "WebTitle" in p:
                    # continue
                    web = re.findall(r"\[\*\] WebTitle: (http|https)\:\/\/(\d+\.\d+\.\d+\.\d+)\:*(\d*).*title\:(.*)\s",
                                     data)
                    # print(web)
                    # print(web[0])
                    try:
                        if "http" in web[0][0]:
                            if web[0][2] == "":
                                port = "80"
                            else:
                                port = web[0][2]
                            print("protocol: " + web[0][0] + "  ip: " + web[0][
                                1] + "  port: " + port + "  service(web title): " + web[0][3])
                    except:
                        continue

                elif "NetBios" in p:
                    # print(data)
                    netbios = re.findall(r"\[\*\] NetBios: (.*?)\s(\w+\\*\w+)", data)
                    # print(netbios[0])
                    print("protocol: " + "NetBios" + "  ip: " + netbios[0][0] + "  service: " + netbios[0][1])
                else:
                    print(data)


def randstr( len=8):
    import string
    import random
    d = string.ascii_letters + string.digits
    str_list = [random.choice(d) for i in range(len)]
    random_str = ''.join(str_list)
    return random_str


ip = "45.126.125.0/24"
ip = "192.168.239.0/24"
ip = "159.65.92.0/24"
ip = "66.151.67.0/24"

if os.name == 'nt':
    cmd=".\\tools\\fscan\\fscan.exe"
    filepath = "tmp\\fscan\\"
elif os.name == 'posix':
    cmd="tools/fscan/fscan"
    filepath = "tmp/fscan/"

cmd = cmd + f" -nopoc -nobr -h {ip}"
print(cmd)
result = subprocess.run(cmd, shell=True, capture_output=True)

if result.returncode == 0:
    # logger.debug("SERVICE: fscan run")
    print("SERVICE: fscan run")

    import re
    output_string = result.stdout.decode()
    print(output_string)
    fscan_output_file(output_string,ip)
    print("-------------------------------------------")
    # regx = r"(\d+\.\d+\.\d+\.\d+)\:(\d+)\sopen"
    # match = re.search(regx, output_string)
    # if match:
    #     ## 查询所有ip并存入列表
    #     ip_list = re.findall(regx, output_string)
    #     for alive_ip in ip_list:
    #         print(alive_ip)
    # else:
    #     print("PORT: fscan version UNKNOWN")

else:
    print("SERVICE: fscan error")


#### --service

Oslist(filepath,ip)



