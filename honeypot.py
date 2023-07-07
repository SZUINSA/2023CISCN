import base64
import time
import nmap


class method_fofa:
    def __init__(self, db, logger, name="honeypot-fofa"):
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
            self.logger.info("HONEYPOT: fofa apikey load")
        else:
            self.logger.info("HONEYPOT: fofa apikey error")

    def honeypot(self, target):
        import json
        import requests
        query = f"app=\"蜜罐\" && ip=\"{target}\"";
        query = base64.b64encode(query.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?email={self.email}&key={self.key}&qbase64={query}&fields=host,ip,port,server"
        response = requests.get(url, proxies=self.proxies)
        json = json.loads(response.text)
        self.logger.debug(json)
        if json['error'] == False:
            for item in json['results']:
                import re
                match = re.match(r"^(.*?)/", item[3])
                if match:
                    result = item[2] + "/" + match.group(1)
                else:
                    result = item[2] + "/" + item[3]
                self.logger.debug(result)
                self.db.add_honeypot(target,result)
            self.logger.debug("HINEYPOT: fofa run")
        else:
            self.logger.debug("HINEYPOT: fofa error")


class app:
    def __init__(self, db, logger, method='honeypot-fofa'):
        self.db = db
        self.logger = logger
        if method == 'honeypot-quake':
            self.method = method_quake(db, logger)
        else:
            self.method = method_fofa(db, logger)

    def run(self, sleep=60):

        self.method.honeypot("207.144.250.6")

        ''' 
        while True:
            ip = self.db.get_ip_no_scan(self.method.name)
            if ip is not None:
                self.logger.info("HONEYPOT-CHECK %s %s" % (self.method.name,ip,))
                self.db.update_ip_scan_timestamp(self.method.name,ip)
            
                result = self.method.scan(ip)
                try:
                    for item in result:
                        self.db.add_ip(item)
                    self.logger.debug(str(result))
                except Exception:
                    pass
            
                self.logger.info("HONEYPOT-CHECK %s %s SUCCESS" % (self.method.name,ip,))
            else:
                self.logger.debug("HONEYPOT: sleep")
                time.sleep(sleep)
        '''
