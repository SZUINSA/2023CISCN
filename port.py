import time
import nmap


class method_nmap:
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
                logger.warning("PORT: nmap version UNKNOWN")
        else:
            logger.warning("PORT: nmap not found")

    def port(self, target):
        # TODO: port

        # nm = nmap.PortScanner()
        # nm.scan(hosts=target, arguments='-F')
        return self.fastscan(target)


    def fastscan(self,target="192.168.239.61"):
        self.name = "port-nmap-fastscan"
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-F')

        return nm



class method_nmap_port_fastscan:
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
        # TODO: port
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sS')
        return nm

class app:
    def __init__(self, db, logger,method='port-nmap'):
        self.db = db
        self.logger = logger
        if method == 'port-nmap':
            self.method = method_nmap(db,logger)

    def run(self, sleep=60):

        ## 端口探测
        # ip = "192.168.239.61"

        while True:
            ip = self.db.get_ip_no_port(self.method.name)
            if ip is not None:

                self.logger.info("PORT-CHECK %s %s" % (self.method.name,ip,))
                # self.logger.info("PORT-CHECK %s %s" % (self.method.name,"192.168.239.61",))
                self.db.update_ip_port_timestamp(self.method.name,ip)
                #TODO: self.method.port(ip)

                result = self.method.port(ip)
                # for item in result:
                #     self.db.add_services(ip, port)
                #
                for host in result.all_hosts():
                    print('----------------------------------------------------')
                    print('Host : %s (%s)' % (host, result[host].hostname()))
                    print('State : %s' % result[host].state())
                    for proto in result[host].all_protocols():
                        print('----------')
                        print('Protocol : %s' % proto)
                        lport = result[host][proto].keys()
                        for port in lport:
                            print(f'Port: {port}  State: {result[host][proto][port]["state"]}')
                            if result[host][proto][port]["state"] == "open":
                                self.db.add_services(host,port)

                self.logger.debug(str(result))
                self.logger.info("PORT-CHECK %s %s SUCCESS" % (self.method.name,ip,))
            else:
                self.logger.debug("PORT: sleep")
                time.sleep(sleep)


