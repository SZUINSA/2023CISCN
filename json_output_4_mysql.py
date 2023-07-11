
import os
import json
import re
import mysqldb
import logging
import sys
import logging

def get_ip(data):

    datastr = str(data)
    pattern_ip = re.compile("\'(\d+\.\d+\.\d+\.\d+)\'")
    ipname_list = re.findall(pattern_ip, datastr)
    # print(ipname_list)
    return ipname_list

def get_honneypot(data,ip):
    datastr = str(data[ip])
    pattern_honneypot = re.compile("\s\'(\d+\/.*?)\'")
    honneypot_list = re.findall(pattern_honneypot, datastr)
    # print(honneypot_list)
    return honneypot_list

def logs(filename='logs.txt', level=logging.DEBUG):
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    fh = logging.FileHandler(filename)
    fh.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    formatter = logging.Formatter(
        "[%(asctime)s]\t[%(thread)d]\t[%(filename)s]\t[line: %(lineno)d]\t[%(levelname)s]\t#%(message)s")
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

def real_add_honeypot():
    # 这个测试没问题了

    filepath = "tmp/honneypot/"
    filelist = os.listdir(filepath)
    for filename in filelist:
        # print(filename)
        with open(filepath + filename) as file:
            data = json.load(file)

            print(data)
            ip_list = get_ip(data)
            for ip in ip_list:
                honeypot_list = get_honneypot(data, ip)
                for honeypot in honeypot_list:
                    print(ip," ",honeypot)

                    # db.add_honeypot('16.163.13.106', honeypot)
                    db.add_honeypot('\''+ip+'\'',honeypot)

def manage_honeypot(honeypot):
    honeypot_list = []
    if honeypot == '':
        return "null"
    pattern_honeypot = re.compile("@#([\d|\/|\w]+)")
    ipname_list = re.findall(pattern_honeypot, honeypot)
    for ipname in ipname_list:
        if ipname not in honeypot_list:
            honeypot_list.append(ipname)
    return honeypot_list


def manage_protocol(protocol):
    if protocol == None:
        return "null"
    if protocol[2:] == '':
        return "null"

    if "@#" in protocol:
        protocol_list = protocol.split("@#")
        return protocol_list[0]

    return protocol[2:]

def manage_serviceapp(service_app):

    print(service_app)
    serviceapp_list = []
    if service_app == None:
        return "null"
    if service_app == '':
        return "null"
    # 有些数据真的骚，有\r\n
    service_app = service_app.replace("\r\n", "")
    service_app_list = []
    # 根据@#分割，返回数组
    service_app_list_tmp = service_app.split("@#")
    for service_app_list_ in service_app_list_tmp:
        # 根据\t; 分割，返回数组
        service_app_list_tmp2 = service_app_list_.split("\t; ")
        if "MiniServ/(" in service_app:
            service_app_list_tmp2 = service_app_list_.split("; ")
        # print(service_app_list_tmp2)
        for i in service_app_list_tmp2:
            # 全部结果塞到service_app_list里
            service_app_list.append(i.strip('\t'))

    # 去重
    for service_app_ in service_app_list:
        if service_app_ not in serviceapp_list:
            serviceapp_list.append(service_app_)
    serviceapp_list.pop(0)

    # 判断是否有版本，没有则/N
    for i in range(len(serviceapp_list)):
        if "/" not in serviceapp_list[i] :
            serviceapp_list[i] = serviceapp_list[i] + '/N'
        elif "/N" in serviceapp_list[i]:
            continue
        elif "OpenSSH" in serviceapp_list[i]:
            # 处理这种骚的： OpenSSH/7.6p1 Ubuntu 4ubuntu0.5
            # 处理这种骚的： OpenSSH/for_Windows_7.7
            pattern_version = re.compile("\/.*?([\d|\.]+)")
            version_list = re.findall(pattern_version, serviceapp_list[i])
            pos = serviceapp_list[i].find("/")
            serviceapp_list[i] = serviceapp_list[i][:pos+1] + version_list[0]
        elif "MiniServ/(" in serviceapp_list[i]:
            # # 处理这种骚的：@#MiniServ/([\d.]+)\r\n|s p; MiniServ; Webmin httpd

            print(serviceapp_list[i])
            # serviceapp_list[i] = serviceapp_list[i].replace("([\d.]+)\r\n|s p","")
            # try :
            #     pattern_version = re.compile("\/.*?(\d+[\d|\.]+)")
            #     version_list = re.findall(pattern_version, serviceapp_list[i])
            # except :
            version_list = []
            version_list.append("N")
            pos = serviceapp_list[i].find("/")
            serviceapp_list[i] = serviceapp_list[i][:pos + 1] + version_list[0]
        elif "Apache Jserv" in serviceapp_list[i]:
            version_list = []
            version_list.append("N")
            pos = serviceapp_list[i].find("/")
            serviceapp_list[i] = serviceapp_list[i][:pos + 1] + version_list[0]


        else:
            pattern_version = re.compile("\/([\d|\.]+)")
            version_list = re.findall(pattern_version, serviceapp_list[i])
            pos = serviceapp_list[i].find("/")
            serviceapp_list[i] = serviceapp_list[i][:pos+1] + version_list[0]

    # 再次去重
    new_list = []
    [new_list.append(x) for x in serviceapp_list if x not in new_list]

    return new_list

def manage_service(service):
    service_list = []
    service_element = {}
    for i in service:
        service_element = {
            "port": int(i[0]),
            "protocol": manage_protocol(i[1]),
            "service_app": manage_serviceapp(i[2]),

        }
        service_list.append(service_element)
    return service_list



logger = logs(level=logging.WARNING)
logger.info("Program Start")
db = mysqldb.db(logger)


# service = db.get_service_from_ip("45.83.43.23")
# print(service)

# print(manage_serviceapp("@#Microsoft ftp/N"))
# print(manage_serviceapp("@#OpenSSH/for_Windows_7.7"))
# print(manage_serviceapp("@#OpenSSH/7.6p1 Ubuntu 4ubuntu0.5"))
# print(manage_serviceapp("@#MiniServ/([\d.]+)\r\n|s p; MiniServ; Webmin httpd"))
# print(manage_serviceapp("@#Apache Jserv/ i"))




json_ip_list = {}
json_ip = ''

ip_list = []
ip_list = db.get_all_ip()
# print(ip_list)

for ip in ip_list:

    # 根据主办方要求缩小范围
    if not default.ip_in_list(ip):
        continue

    service = db.get_service_from_ip(ip)
    service = manage_service(service)


    deviceinfo = db.get_deviceinfo_from_ip(ip) #缺乏数据，理论上可以了

    honeypot = db.get_honeypot_from_ip(ip) # 测试可以
    honeypot = manage_honeypot(honeypot)

    timestamp = db.get_timestamp_from_ip(ip) # 测试可以

    ipdata = {
        "services": service,
        "deviceinfo": deviceinfo,
        "honeypot": honeypot,
        "timestamp": str(timestamp)
    }


    json_ip = {ip: ipdata}
    if service != ["null"]:
        print(json_ip)

    # print(json.dumps(json_ip))
    # print(json_ip)
    json_ip_list.append(json_ip)


with open("output.json", "w") as f:
    json.dump(json_ip_list, f)


