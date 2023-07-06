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
            file = 'tmp\\'+self.randstr()+'.txt'
        elif os.name == 'posix':
            cmd="tools/kscan/kscan"
            file = 'tmp/'+self.randstr()+'.txt'

        cmd = cmd + f" --target {ip} --port {port} -oJ {file}"

        result = subprocess.run(cmd, shell=True, capture_output=True)

        if result.returncode == 0:
            self.logger.debug("SERVICE: kscan run")
            with open(file,"rb") as f:
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
class app:
    def __init__(self, db, logger,method='service-kscan'):
        self.db = db
        self.logger = logger
        if method == 'service-kscan':
            self.method = method_kscan(db,logger)

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

                            if not services_app is None:
                                self.db.add_service_app(ip, port, services_app)

                            self.logger.debug(str(protocol), str(services_app))

                        except Exception:
                            pass

                        self.logger.info("SERVICES-CHECK %s %s %s SUCCESS" % (self.method.name,ip,port))
                else:
                    self.logger.debug("SERVICES: sleep")
                    time.sleep(sleep)
            except Exception:
                self.logger.debug("SERVICES: sleep")
                time.sleep(sleep)

