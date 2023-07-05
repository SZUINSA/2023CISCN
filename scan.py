import time
import nmap
class app:
    #def __init__(self):
    def run(self,db,logger,sleep=60):
        while True:
            ip = db.get_ip_no_scan()
            if ip is not None:
                logger.info("SCAN %s"%(ip,))
                nm = nmap.PortScanner()
                nm.scan(hosts=ip, arguments='-sS')
                for item in nm.all_hosts():
                    db.add_ip(item)
                logger.debug(str(nm.all_hosts()))
                db.update_ip_scan_timestamp(ip)
            else:
                logger.debug("SCAN: sleep")
                time.sleep(sleep)