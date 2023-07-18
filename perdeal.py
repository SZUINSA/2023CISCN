import mysqldb
import main
import logging
import json

def api():
    logger = main.logs()
    logger.info("Program Start")
    db = mysqldb.db(logger)
    iplist = db.get_all_ip()
    flag = 0
    for ip in iplist:
        print(ip)
        content_str = db.get_api_from_ip_and_method(ip, "port-fofa")
        if content_str is not None:
            content = json.loads(content_str)
            for i in content["results"]:
                try:
                    serviceapp = i[4].replace(',', '\t; ')
                except:
                    serviceapp = i[4]
                db.add_services(i[1], i[2])
                db.add_service_app(i[1], i[2], serviceapp)