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

# real_add_honeypot()


json_ip_list = []
json_ip = ''

ip_list = []
ip_list = db.get_all_ip()

# print(ip_list)

for ip in ip_list:
    # print(ip)  #16.163.13.0

    deviceinfo = db.get_deviceinfo_from_ip(ip) #缺乏数据，理论上可以了
    # print(deviceinfo)

    honeypot = db.get_honeypot_from_ip(ip) # 测试可以
    # print(honeypot)

    timestamp = db.get_timestamp_from_ip(ip) # 测试可以
    # print(timestamp)

    ipdata = '{' \
             '"services": [],' \
             '"deviceinfo": "%s",' \
             '"honeypot": [%s],' \
             '"timestamp": %s'\
             '}' % (deviceinfo, honeypot, timestamp)
    json_ip = '{"%s": %s}' % (ip,ipdata)
    print(json_ip)
    json_ip_list.append(json_ip)