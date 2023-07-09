import time
import base64
import nmap


class method_nmap:

    name = "port-nmap"

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


    def fastscan(self,target):
        self.name = "port-nmap-fastscan"
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-F')

        if not nm:
            self.logger.debug("nmap fastscan can't find port")
        else:
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        if nm[host][proto][port]["state"] == "open":
                            self.db.add_services(host, port)

        return []


class method_nmap_allscan:
    name = "port-nmap-allscan"

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
        return self.allscan(target)

    def allscan(self, target):
        self.name = "port-xxxx-allscan"
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-p1-65535')

        if not nm:
            self.logger.debug("nmap allscan(1-65535) can't find port")
        else:
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        if nm[host][proto][port]["state"] == "open":
                            self.db.add_services(host, port)

        return []

class method_fofa:
    name = "port-fofa"
    def __init__(self, db, logger, name="port-fofa"):
        self.db = db
        self.logger = logger
        self.name = name
        import os
        import json
        import requests
        self.email = os.environ['fofa_email']
        self.key = os.environ['fofa_key']
        self.proxies = {"http": "", "https": ""}
        url = f"https://fofa.info/api/v1/info/my?email={self.email}&key={self.key}"
        response = requests.get(url, proxies=self.proxies)
        logger.debug(response.text)
        json = json.loads(response.text)
        if json['error'] == False:
            self.logger.info("PORT: fofa apikey load")
        else:
            self.logger.info("PORT: fofa apikey error")
    def port(self, target):
        import json
        import requests
        query = f"ip=\"{target}\"";
        query = base64.b64encode(query.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?email={self.email}&key={self.key}&qbase64={query}&fields=host,ip,port,server,product,product_category"
        response = requests.get(url, proxies=self.proxies)
        json = json.loads(response.text)
        self.logger.debug(json)
        if json['error'] == False:
            self.db.add_api(target,self.name,response.text)
            self.logger.debug("PORT: fofa run")
        else:
            self.logger.debug("PORT: fofa error")
        time.sleep(1)
        return None
class method_fscan_port:

    def __init__(self, db, logger,name = "port-fscan-port"):
        self.db = db
        self.logger = logger
        self.name=name
        import os
        if os.name == 'posix':
            if not os.path.exists('tools/fscan/fscan'):
                self.logger.warning("PORT: fscan not found")
            else:
                self.logger.info("PORT: fscan found")

        elif os.name == 'nt':
            if not os.path.exists('tools/fscan/fscan.exe'):
                self.logger.warning("PORT: fscan not found")
            else:
                self.logger.info("PORT: fscan found")
        else:
            self.logger.info("PORT: fscan not support")
    def port(self, target):

        result = self.fscan_port(target)
        if result:
            for alive_ip in result:
                self.db.add_services(alive_ip[0], alive_ip[1])
            self.logger.debug(str(result))

        return []

    def fscan_port(self,target):
        import os
        import subprocess

        if os.name == 'nt':
            cmd = "tools\\fscan\\fscan.exe"
        elif os.name == 'posix':
            cmd = "tools/fscan/fscan"

        cmd = cmd + f" -nopoc -nobr -h {target}"

        result = subprocess.run(cmd, shell=True, capture_output=True)

        if result.returncode == 0:
            self.logger.debug("PORT: fscan run")

            import re
            output_string = result.stdout.decode()
            self.fscan_output_file(output_string, target)
            regx = r"(\d+\.\d+\.\d+\.\d+)\:(\d+)\sopen"
            match = re.search(regx, output_string)
            if match:
                ip_list = re.findall(regx, output_string)

                return ip_list
            else:
                self.logger.debug("PORT: fscan can't find ports")
                return []
        else:
            self.logger.debug("PORT: fscan error")
            return []

    def fscan_output_file(self, result, target):
        import os

        if os.name == 'nt':
            filepath = "tmp\\fscan\\"
        elif os.name == 'posix':
            filepath = "tmp/fscan/"
        if not os.path.exists(filepath):
            os.mkdir(filepath)
        with open(f'{filepath}fscan_{target.strip()}.txt', 'w') as f:
            f.write(result)


class app:
    def __init__(self, db, logger,method='port-nmap'):
        self.db = db
        self.logger = logger
        if method == 'port-fofa':
            self.method = method_fofa(db, logger)
        elif method == "port-fscan":
            self.method = method_fscan_port(db, logger)
        elif method == "port-allscan":
            self.method = method_nmap_allscan(db, logger)
        else:
            self.method = method_nmap(db, logger)


    def run(self, sleep=60):


        while True:
            ip = self.db.get_ip_no_port(self.method.name)
            if ip is not None:
                self.logger.info("PORT-CHECK %s %s" % (self.method.name,ip,))
                self.db.update_ip_port_timestamp(self.method.name,ip)
                result = self.method.port(ip)


                # self.logger.debug(str(result))
                self.logger.info("PORT-CHECK %s %s SUCCESS" % (self.method.name,ip,))
            else:
                self.logger.debug("PORT: sleep")
                time.sleep(sleep)

