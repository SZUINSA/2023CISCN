import json
import os
import mysqldb
import logging
import main

def deal_quake():
    ## init db
    logger = main.logs()
    # logger = main.logs()
    logger.info("Program Start")
    db = mysqldb.db(logger)


    ## 提取 diviceinfo , port, 协议（protocol），服务（server)

    filePath1 = 'tmp/quake/'
    fileList = os.listdir(filePath1)

    flag = 0

    for file in fileList:
        print("[*] file: " + file)
        print("[*] working ... ... ...")
        ### 读取json文件储存到 data 中
        with open(filePath1 + file, 'r') as f:
            data = json.load(f)
        ### 提取 diviceinfo , port, 协议（protocol），服务（server)
        data = data['data']

        sth_to_write = {}

        ## todo
        ## add_service_app 47.243.241.29 80 PHP/N
        ## pymysql.err.DataError: (1406, "Data too long for column 'SERVICE_APP' at row 484")


        for i in range(len(data)):
            ip = data[i]['ip']
            port = data[i]['port']
            transport = data[i]['transport']
            service_name = data[i]['service']['name']

            if ip == '47.243.241.29':
                flag = 1
            if flag == 0:
                continue

            if transport == 'tcp':


                print(ip + ':' + str(port) + ' ' + transport + ' is tcp ' + service_name)
                # print(data[i])

                db.add_ip(ip)
                db.add_services(ip,str(port))
                try:
                    db.add_protocol(ip,str(port),service_name)
                except:
                    pass

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
                    try:
                        db.add_service_app(ip,str(port),components[j]['product_name_en'] + "/" + version)
                    except :
                        print(ip)
                        pass

                # sth_to_write[i] = {"ip":ip,"port":port,"transport":transport,"service_name":service_name}


deal_quake()


# ## init db
# logger = main.logs()
# # logger = main.logs()
# logger.info("Program Start")
# db = mysqldb.db(logger)
# db.add_protocol('103.252.118.176','7980','http')


