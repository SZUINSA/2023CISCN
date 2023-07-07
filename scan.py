import time
import nmap


class method_nmap:
    def __init__(self, db, logger, name = "scan-nmap"):
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
                logger.debug(f"SCAN: nmap version {version_number}")
            else:
                logger.warning("SCAN: nmap version UNKNOWN")
        else:
            logger.warning("SCAN: nmap not found")

    def scan(self, target):
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sS')
        return nm.all_hosts()

class method_fscan:
    def __init__(self, db, logger, name = "scan-fscan"):
        self.db = db
        self.logger = logger
        self.name = name
        logger.info("SCAN: fscan load")

    def scan(self, target):

        import os
        import subprocess
        if os.name == 'nt':
            cmd = ".\\tools\\fscan\\fscan.exe"
        elif os.name == 'posix':
            cmd = "tools/fscan/fscan"

        cmd = cmd + f" -nopoc -pn 1-65535 -h {target}"
        result = subprocess.run(cmd, shell=True, capture_output=True)

        if result.returncode == 0:
            self.logger.debug("SERVICE: fscan run")
            import re
            output_string = result.stdout.decode()
            match = re.search(r"\(icmp\)\sTarget\s(.*)\sis\salive", output_string)
            if match:
                regx = "\(icmp\)\sTarget\s(.*)\sis\salive"
                ip_list = re.findall(regx, output_string)
                return ip_list
            else:
                self.logger.debug("PORT: fscan version UNKNOWN")
        else:
            self.logger.debug("SERVICE: fscan error")


class app:
    def __init__(self, db, logger,method='scan-nmap'):
        self.db = db
        self.logger = logger
        if method == 'scan-fscan':
            self.method = method_fscan(db, logger)
        else:
            self.method = method_nmap(db, logger)

    def run(self, sleep=60):

        while True:
            ip = self.db.get_ip_no_scan(self.method.name)
            if ip is not None:
                self.logger.info("SCAN-CHECK %s %s" % (self.method.name,ip,))
                self.db.update_ip_scan_timestamp(self.method.name,ip)

                result = self.method.scan(ip)
                try:
                    for item in result:
                        self.db.add_ip(item)
                    self.logger.debug(str(result))
                except Exception:
                    pass

                self.logger.info("SCAN-CHECK %s %s SUCCESS" % (self.method.name,ip,))
            else:
                self.logger.debug("SCAN: sleep")
                time.sleep(sleep)
