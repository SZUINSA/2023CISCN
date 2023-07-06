
import re
import os
import json
import subprocess





def randstr( len=8):
    import string
    import random
    d = string.ascii_letters + string.digits
    str_list = [random.choice(d) for i in range(len)]
    random_str = ''.join(str_list)
    return random_str


ip = "192.168.239.0/24"


if os.name == 'nt':
    cmd=".\\tools\\fscan\\fscan.exe"
    file = 'tmp\\'+ randstr() +'.txt'
    # print(file)
elif os.name == 'posix':
    cmd="tools/fscan/fscan"
    file = 'tmp/'+ randstr() +'.txt'

cmd = cmd + f" -nopoc -pn 1-65535 -h {ip}"
# print(cmd)
result = subprocess.run(cmd, shell=True, capture_output=True)

if result.returncode == 0:
    # logger.debug("SERVICE: fscan run")
    print("SERVICE: fscan run")

    import re
    output_string = result.stdout.decode()
    print(output_string)
    print("-------------------------------------------")
    match = re.search(r"\(icmp\)\sTarget\s(.*)\sis\salive", output_string)
    if match:
        ## 查询所有ip并存入列表
        regx = "\(icmp\)\sTarget\s(.*)\sis\salive"
        ip_list = re.findall(regx, output_string)
        for alive_ip in ip_list:
            print(alive_ip)
    else:
        print("PORT: fscan version UNKNOWN")

else:
    print("SERVICE: fscan error")

#输出IP段内存货数量
def AliveIp(datalist):

    sheetList = [['IP段', '段存活数量']]

    for t in datalist:
        Ip_d = re.findall(r"\[\*]\sLiveTop\s\d+\.\d+\.\d+\.\d+/\d+.*", t)

        if len(Ip_d) != 0:
            p1 = list(Ip_d)

            for u in p1:
                ip_duan = re.findall(r"\d+\.\d+\.\d+\.\d+/\d+", u)
                No = re.findall(r"\d+$", u)
                ip_duan.append(No[0])
                sheetList.append(ip_duan)
    print(sheetList)

#输出识别到的系统
def Oslist(datalist):

    replaceList = ["[*]", '\t', "\x01", '\x02']

    sheetList = [['ip', 'os']]

    for t in datalist:
        p = re.findall(r"\[\*]\s\d+\.\d+\.\d+\.\d+.*", t)

        if len(p) != 0:
            p1 = list(p)

            for u in p1:
                ip = re.findall(r"\d+\.\d+\.\d+\.\d+", u)
                #删除无用字符
                for q in replaceList:
                    u = u.replace(q, "")

                ip.append(u.replace(ip[0], '').strip())
                sheetList.append(ip)
