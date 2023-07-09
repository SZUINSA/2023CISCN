import logging
import time
import nmap


class method_kscan:
    name = "service-kscan"

    def __init__(self, db, logger):
        self.db = db
        self.logger = logger
        import os

        if os.name == 'posix':
            if not os.path.exists('tools/kscan/kscan'):
                self.logger.warning("SERVICES: kscan not found")
            else:
                self.logger.info("SERVICES: kscan found")

        elif os.name == 'nt':
            if not os.path.exists('tools/kscan/kscan.exe'):
                self.logger.warning("SERVICES: kscan not found")
            else:
                self.logger.info("SERVICES: kscan found")
        else:
            self.logger.info("SERVICES: kscan not support")

    def randstr(self,len=8):
        import string
        import random
        d=string.ascii_letters + string.digits
        str_list = [random.choice(d) for i in range(len)]
        random_str = ''.join(str_list)
        return random_str
    def services(self, ip,port):
        import os
        import json
        import subprocess
        if os.name == 'nt':
            cmd="tools\\kscan\\kscan.exe"
            file = 'tmp\\kscan\\'
        elif os.name == 'posix':
            cmd="tools/kscan/kscan"
            file = 'tmp/kscan/'

        if not os.path.exists(file):
            os.mkdir(file)

        name = self.randstr()+'.txt'
        cmd = cmd + f" --target {ip} --port {port} -oJ {file+name}"

        result = subprocess.run(cmd, shell=True, capture_output=True)

        if result.returncode == 0:
            self.logger.debug("SERVICE: kscan run")
            with open(file+name,"rb") as f:
                load=f.read()
                self.logger.debug("SERVICE: "+ load.decode("UTF-8"));
                json=json.loads(load)
                try:
                    self.db.add_protocol(ip, port, json[0]['Service'])
                except Exception:
                    pass

                try:
                    self.db.add_service_app(ip, port, json[0]['FingerPrint'])
                except Exception:
                    pass

                try:
                    try:
                        version=json[0]['Version']
                    except Exception:
                        version='N'
                    self.db.add_service_app(ip, port, json[0]['ProductName']+'/'+version)
                except Exception:
                    pass

            return None,None
        else:
            self.logger.warning("SERVICE: kscan error")
            return None,None


class method_fscan:
    name = "service-fscan"

    def __init__(self, db, logger):
        self.db = db
        self.logger = logger
        import os

        if os.name == 'posix':
            if not os.path.exists("tools\\fscan\\fscan.exe"):
                self.logger.warning("SERVICES: fscan not found")
            else:
                self.logger.info("SERVICES: fscan found")

        elif os.name == 'nt':
            if not os.path.exists("tools/fscan/fscan"):
                self.logger.warning("SERVICES: fscan not found")
            else:
                self.logger.info("SERVICES: fscan found")
        else:
            self.logger.info("SERVICES: fscan not support")

    def Oslist(self,file):
        import re
        with open(file, "rb") as f:
            datalist = f.readlines()
        flag = 0
        for data in datalist:
            data = data.decode(encoding='GBK')
            if "start vulscan" in data:
                flag = 1
            if flag:
                p = re.findall(r"\[\*\]\s(.*?)\:\s", data)
                if p:
                    if "WebTitle" in p:
                        web = re.findall(
                            r"\[\*\] WebTitle: (http|https)\:\/\/(\d+\.\d+\.\d+\.\d+)\:*(\d*).*title\:(.*)\s",
                            data)
                        try:
                            if "http" in web[0][0]:
                                if web[0][2] == "":
                                    port = "80"
                                else:
                                    port = web[0][2]
                                protocol = web[0][0]
                                ip = web[0][1]
                                self.logger.debug("protocol: " + str(web[0][0]) + "  ip: " + str(web[0][
                                    1]) + "  port: " + str(port) + "  service(web title): " + str(web[0][3]))
                                if not protocol is None:
                                    self.db.add_protocol(ip, port, protocol)
                                    self.logger.debug(str(protocol))

                            else:
                                continue
                        except:
                            self.logger.debug(Exception)
                            pass
                    else:
                        print(data)
        return None, None

    def services(self, ip, port):
        import os
        import json
        import subprocess
        if os.name == 'nt':
            cmd="tools\\fscan\\fscan.exe"
            filepath = "tmp\\fscan\\"
        elif os.name == 'posix':
            cmd="tools/fscan/fscan"
            filepath = "tmp/fscan/"
        file = filepath + "fscan_" + ip.strip() + '.txt'

        if not os.path.exists(file):
            self.logger.warning("SERVICES: fscan not found")
            self.logger.warning("SERVICES: Please run with parentment --PORT port-fscan firstly to create files")
        else:
            self.logger.debug("SERVICE: fscan run")
            self.Oslist(file)


class app:
    def __init__(self, db, logger,method='service-kscan'):
        self.db = db
        self.logger = logger
        if method == 'service-kscan':
            self.method = method_kscan(db,logger)
        elif method == "services-fscan-protocol":
            self.method = method_fscan(db,logger)


    def run(self, sleep=60):
        while True:
            try:
                ip,port = self.db.get_ip_no_services(self.method.name)
                if ip is not None:
                    self.logger.info("SERVICES-CHECK %s %s %s" % (self.method.name,ip,port))
                    self.db.update_ip_services_timestamp(self.method.name,ip,port)

                    try:
                        protocol,services_app=self.method.services(ip,port)
                        if not protocol is None:
                            self.db.add_protocol(ip, port, protocol)
                            self.logger.debug(str(protocol))

                        if not services_app is None:
                            self.db.add_service_app(ip, port, services_app)
                            self.logger.debug(str(services_app))

                    except Exception:
                        pass

                    self.logger.info("SERVICES-CHECK %s %s %s SUCCESS" % (self.method.name,ip,port))

                else:
                    self.logger.debug("SERVICES: sleep")
                    time.sleep(sleep)
            except Exception:
                self.logger.debug("SERVICES: sleep")
                time.sleep(sleep)

