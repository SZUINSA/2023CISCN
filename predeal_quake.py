import json
import os
import mysqldb
import logging
import main

def deal_quake():
    ## init db
    logger = main.logs(level=logging.WARNING)
    # logger = main.logs()
    logger.info("Program Start")
    db = mysqldb.db(logger)


    ## 提取 diviceinfo , port, 协议（protocol），服务（server)

    filePath1 = 'tmp/quake/'
    fileList = os.listdir(filePath1)
    for file in fileList:
        print("[*] file: " + file)
        print("[*] working ... ... ...")
        ### 读取json文件储存到 data 中
        with open(filePath1 + file, 'r') as f:
            data = json.load(f)
        ### 提取 diviceinfo , port, 协议（protocol），服务（server)
        data = data['data']

        sth_to_write = {}

        for i in range(len(data)):
            ip = data[i]['ip']
            port = data[i]['port']
            transport = data[i]['transport']
            service_name = data[i]['service']['name']
            if transport == 'tcp':
                print(ip + ':' + str(port) + ' ' + transport + ' is tcp ' + service_name)
                # print(data[i])
                try:
                    components = data[i]['components']
                except:
                    pass
                for j in range(len(components)):
                    if components[j]['version'] == '':
                        version = 'N'
                    else:
                        version = components[j]['version']
                    print(components[j]['product_name_en'] + "/" + version)
                    db.add_service_app(components[j]['product_name_en'] + "/" + version,ip,str(port))
                sth_to_write[i] = {"ip":ip,"port":port,"transport":transport,"service_name":service_name}
                db.add_ip(ip)
                db.add_services(ip,str(port))
                db.add_protocol(service_name,ip,str(port))

# deal_quake()

