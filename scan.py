import time
import nmap
class app:
    def __init__(self,db,logger):
        self.db=db
        self.logger=logger

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
                logger.warning("SCAN: nmap version UNKNOW")
        else:
            logger.warning("SCAN: nmap not found")
    def run(self,sleep=60):
        while True:
            ip = self.db.get_ip_no_scan()
            if ip is not None:
                self.logger.info("SCAN %s"%(ip,))
                nm = nmap.PortScanner()
                nm.scan(hosts=ip, arguments='-sS')
                for item in nm.all_hosts():
                    self.db.add_ip(item)
                self.logger.debug(str(nm.all_hosts()))
                self.db.update_ip_scan_timestamp(ip)
            else:
                self.logger.debug("SCAN: sleep")
                time.sleep(sleep)