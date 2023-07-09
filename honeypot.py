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

class method_quake_dump:
    def __init__(self, db, logger, name="honeypot-quake-dump"):
        self.db = db
        self.logger = logger
        self.name = name
        import os
        try:
            self.path = os.environ['quake_dump_file']
            self.logger.info("HONEYPOT: quake_dump_file load")
        except Exception:
            self.logger.info("HONEYPOT: quake_dump_file error")

    def get_ip(self,data):
        import re
        datastr = str(data)
        pattern_ip = re.compile("\'(\d+\.\d+\.\d+\.\d+)\'")
        ipname_list = re.findall(pattern_ip, datastr)
        return ipname_list
    def get_honneypot(self,data, ip):
        import re
        datastr = str(data[ip])
        pattern_honneypot = re.compile("\s\'(\d+\/.*?)\'")
        honneypot_list = re.findall(pattern_honneypot, datastr)
        return honneypot_list
    def real_add_honeypot(self,target):
        import os
        import json
        filepath = self.path
        filelist = os.listdir(filepath)
        for filename in filelist:
            try:
                with open(filepath + filename) as file:
                    data = json.load(file)
                    #ip_list = get_ip(data)
                    honeypot_list = self.get_honneypot(data,target)
                    for honeypot in honeypot_list:
                        try:
                            self.db.add_honeypot(target, honeypot)
                        except Exception:
                            self.logger.warning("HONEYPOT: ip in file not available")
            except Exception:
                pass
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
        if method == 'honeypot-quake-dump':
            self.method = method_quake_dump(db, logger)
        else:
            self.method = method_fofa(db, logger)

    def run(self, sleep=60):

        while True:
            ip = self.db.get_ip_no_services(self.method.name)
            if ip is not None:
                self.logger.info("HONEYPOT-CHECK %s %s" % (self.method.name,ip,))
                self.db.update_ip_scan_timestamp(self.method.name,ip)
            
                result = self.method.honeypot(ip)
                try:
                    self.db.add_ip(ip,result)
                    self.logger.debug(str(result))
                except Exception:
                    pass
            
                self.logger.info("HONEYPOT-CHECK %s %s SUCCESS" % (self.method.name,ip,))
            else:
                self.logger.debug("HONEYPOT: sleep")
                time.sleep(sleep)
