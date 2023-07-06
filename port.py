import time
import nmap


class method_nmap:

    def __init__(self, db, logger, name = "port-nmap"):
        self.db = db
        self.logger = logger
        self.name = name
        import subprocess
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
            logger.warning("PORT: nmap not found")

    def port(self, target):
        return self.fastscan(target)

    def port_xxxx(self, target):
        return self.allscan(target)

    def port_fscan(self,target):
        return self.fscan_port(target)

    def fastscan(self,target):
        self.name = "port-nmap-fastscan"
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-F')
        return nm

    def allscan(self, target):
        self.name = "port-xxxx-allscan"
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-p1-65535')
        return nm

    def fscan_port(self,target):
        import os
        import subprocess

        if os.name == 'nt':
            cmd = ".\\tools\\fscan\\fscan.exe"
        elif os.name == 'posix':
            cmd = "tools/fscan/fscan"

        cmd = cmd + f" -nopoc -h {target}"
        result = subprocess.run(cmd, shell=True, capture_output=True)

        if result.returncode == 0:
            self.logger.debug("SERVICE: fscan run")

            import re
            output_string = result.stdout.decode()

            regx = r"(\d+\.\d+\.\d+\.\d+)\:(\d+)\sopen"
            match = re.search(regx, output_string)
            if match:
                ip_list = re.findall(regx, output_string)
                return ip_list
            else:
                self.logger.debug("PORT: fscan can't find ports")

        else:
            self.logger.debug("SERVICE: fscan error")

class method_nmap_xxx:
    name = "port-nmap"

    def __init__(self, db, logger):
        self.db = db
        self.logger = logger
        import subprocess
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
                logger.warning("PORT: nmap version UNKNOW")
        else:
            logger.warning("PORT: nmap not found")

    def port(self, target):
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sS')
        return nm

class app:
    def __init__(self, db, logger,method='port-nmap'):
        self.db = db
        self.logger = logger
        if method == 'port-nmap':
            self.method = method_nmap(db, logger, method)
        elif method == "port-fscan":
            self.method = method_nmap(db, logger, method)
        else:
            self.method = method_nmap(db, logger)

    def run(self, sleep=60):


        while True:
            ip = self.db.get_ip_no_port(self.method.name)
            if ip is not None:
                self.logger.info("PORT-CHECK %s %s" % (self.method.name,ip,))
                self.db.update_ip_port_timestamp(self.method.name,ip)
                if self.method.name == 'port-nmap':
                    result = self.method.port(ip)
                elif self.method.name == 'port-fscan':
                    result = self.method.port_fscan(ip)
                    for alive_ip in result:
                        self.db.add_services(alive_ip[0],alive_ip[1])
                    self.logger.debug(str(result))
                    self.logger.info("PORT-CHECK %s %s SUCCESS" % (self.method.name, ip,))

                    continue

                else:
                    result = self.method.port_xxxx(ip)
                for host in result.all_hosts():
                    for proto in result[host].all_protocols():
                        lport = result[host][proto].keys()
                        for port in lport:
                            if result[host][proto][port]["state"] == "open":
                                self.db.add_services(host,port)

                self.logger.debug(str(result))
                self.logger.info("PORT-CHECK %s %s SUCCESS" % (self.method.name,ip,))
            else:
                self.logger.debug("PORT: sleep")
                time.sleep(sleep)

