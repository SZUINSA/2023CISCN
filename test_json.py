# todo  得到json中目标ip,honneypot,port后，再将其插入到数据库中

import os
import json

import sqlite
import re

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



import sqlite
import logging
import sys
import logging


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

### test   ###3
logger = logs()
logger.info("Program Start")
db = sqlite.db(logger)
# db.add_honeypot('16.163.13.106','honneymt')



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
        honeypot_list = ["null"]
        return honeypot_list
    pattern_honeypot = re.compile("@#([\d|\/|\w]+)")
    ipname_list = re.findall(pattern_honeypot, honeypot)
    for ipname in ipname_list:
        if ipname not in honeypot_list:
            honeypot_list.append(ipname)
    return honeypot_list


def manage_protocol(protocol):
    if protocol[2:] == '':
        return "null"
    return protocol[2:]

def manage_serviceapp(service_app):
    serviceapp_list = []
    if service_app == '':
        serviceapp_list = ["null"]
        return serviceapp_list
    # pattern_serviceapp = re.compile("@#([\d|\/|\w]+)")
    # ipname_list = re.findall(pattern_honeypot, honeypot)
    # service_app_list = []
    service_app_list = service_app.split("@#")
    for service_app_ in service_app_list:
        if service_app_ not in serviceapp_list:
            serviceapp_list.append(service_app_)
    return serviceapp_list


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


service = db.get_service_from_ip("16.163.13.0")
result = manage_service(service)
print(result)





# json_ip_list = []
# json_ip = ''
#
# ip_list = []
# ip_list = db.get_all_ip()
# # print(ip_list)
#
# for ip in ip_list:
#
#     deviceinfo = db.get_deviceinfo_from_ip(ip) #缺乏数据，理论上可以了
#
#     honeypot = db.get_honeypot_from_ip(ip) # 测试可以
#     honeypot = manage_honeypot(honeypot)
#
#     timestamp = db.get_timestamp_from_ip(ip) # 测试可以
#
#
#     ipdata = {
#         "services": [],
#         "deviceinfo": deviceinfo,
#         "honeypot": honeypot,
#         "timestamp": timestamp
#     }
#
#
#     json_ip = {ip: ipdata}
#     # if honeypot != ["null"]:
#     #     print(json.dumps(json_ip))
#     json_ip_list.append(json_ip)


