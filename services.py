import time
import nmap


class method_kscan:
    name = "service-kscan"

    def __init__(self, db, logger):
        self.db = db
        self.logger = logger

        '''import subprocess
        cmd = "nmap --version"
        result = subprocess.run(cmd, shell=True, capture_output=True)
        if result.returncode == 0:
            import re
            version_string = result.stdout.decode()
            match = re.search(r"Nmap version (\d+\.\d+(?:\.\d+)?)", version_string)
            if match:
                version_number = match.group(1)
                logger.debug(f"PORT: nmap version {version_number}")
            else:
                logger.warning("PORT: nmap version UNKNOWN")
        else:
            logger.warning("PORT: nmap not found")'''

    def service(self, target):
        return "RSS"


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

                    result = self.method.service(ip)
                    self.db.add_protocol(ip,port,result)

                    self.logger.debug(str(result))
                    self.logger.info("SERVICES-CHECK %s %s %s SUCCESS" % (self.method.name,ip,port))
                else:
                    self.logger.debug("SERVICES: sleep")
                    time.sleep(sleep)
            finally:
                self.logger.debug("SERVICES: sleep")
                time.sleep(sleep)

