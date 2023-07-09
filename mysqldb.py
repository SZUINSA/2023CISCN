import os
class db:

    def __init__(self, logger):
        self.logger = logger

        import pymysql.cursors
        self.db_conn = pymysql.connect(host='ctf.szu.edu.cn',
                                       user='ciscn',
                                       password='ciscn',
                                       database='ciscn',
                                       cursorclass=pymysql.cursors.DictCursor)
        self.logger.info("Connect Mysql Database Succeed.")
        self.db = self.db_conn.cursor()
        self.logger.info("Building Mysql Database...")
        self.build()
        self.logger.info("Building Mysql Database Succeed.")


    def build(self):

        self.db.execute('''CREATE TABLE IF NOT EXISTS SCAN(
                    ID INTEGER PRIMARY KEY AUTO_INCREMENT,
                    IP VARCHAR(16) NULL,
                    METHOD VARCHAR(1000) DEFAULT '',
                    TIMESTAMP DATETIME NULL
                    );''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS IP(
                    ID INTEGER PRIMARY KEY AUTO_INCREMENT,
                    IP VARCHAR(16) NULL,
                    METHOD VARCHAR(1000) DEFAULT '',
                    DEVICEINFO VARCHAR(5000) DEFAULT '',
                    HONEYPOT VARCHAR(5000) DEFAULT '',
                    TIMESTAMP DATETIME NULL
                    );''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS SERVICES(
                    ID INTEGER PRIMARY KEY AUTO_INCREMENT,
                    IP VARCHAR(16) NULL,
                    METHOD VARCHAR(1000) DEFAULT '',
                    PORT VARCHAR(1000) NULL,
                    PROTOCOL VARCHAR(1000) DEFAULT '',
                    SERVICE_APP VARCHAR(10000) DEFAULT '',
                    TIMESTAMP DATETIME NULL
                    );''')
        self.db_conn.commit()

    def add_scan(self, target):
        self.logger.debug("DB: add_scan %s" % (target,))
        self.db.execute("SELECT count(1) FROM SCAN WHERE IP=%s", (target,))
        self.db_conn.commit()
        i = self.db.fetchone()
        if i['count(1)'] == 0:
            self.db.execute("INSERT INTO SCAN (IP) VALUES (%s)", (target,))
            self.db_conn.commit()
        else:
            self.logger.debug("DB: add_scan %s exits" % (target,))
        return

    def add_ip(self, target):
        self.logger.debug("DB: add_ip %s" % (target,))
        self.db.execute("SELECT count(1) FROM IP WHERE IP=%s", (target,))
        self.db_conn.commit()
        i = self.db.fetchone()
        if i['count(1)'] == 0:
            self.db.execute("INSERT INTO IP (IP) VALUES (%s)", (target,))
            self.db_conn.commit()
        else:
            self.logger.debug("DB: add_ip %s exits" % (target,))
        return

    def add_services(self, target1, target2):
        self.logger.debug("DB: add_services %s %s" % (target1, target2))
        self.db.execute("SELECT count(1) FROM SERVICES WHERE IP=%s and PORT=%s ", (target1, target2))
        self.db_conn.commit()
        i=self.db.fetchone()
        if i['count(1)'] == 0:
            self.db.execute("INSERT INTO SERVICES (IP,PORT) VALUES (%s,%s)", (target1, target2))
            self.db_conn.commit()
        else:
            self.logger.debug("DB: add_services %s %s exits" % (target1, target2))

    def get_ip_no_scan(self, target):
        self.logger.debug("DB: get_ip_no_scan %s" % (target,))
        self.db.execute("SELECT IP from SCAN WHERE METHOD NOT LIKE %s LIMIT 1", ("%@#" + target + "%",))
        self.db_conn.commit()
        i=self.db.fetchone()
        try:
            return i['IP']
        except Exception:
            return None

    def get_ip_no_port(self, target):
        self.logger.debug("DB: get_ip_no_port %s" % (target,))
        self.db.execute("SELECT IP from IP WHERE METHOD NOT LIKE %s LIMIT 1", ("%@#" + target + "%",))
        self.db_conn.commit()
        i=self.db.fetchone()
        try:
            return i['IP']
        except Exception:
            return None

    def get_ip_no_services(self, target):
        self.logger.debug("DB: get_ip_no_services %s" % (target,))
        cursor = self.db.execute("SELECT IP,PORT from SERVICES WHERE METHOD NOT LIKE %s LIMIT 1",
                                 ("%@#" + target + "%",))
        i=self.db.fetchone()
        try:
            return i['IP'], i['PORT']
        except Exception:
            return None

    def add_honeypot(self, target1, target2):
        self.logger.debug("DB: add_honeypot %s %s" % (target1, target2))
        self.db.execute(
            "UPDATE IP SET HONEYPOT=CONCAT(HONEYPOT, %s),TIMESTAMP=DATETIME(CURRENT_TIMESTAMP,'localtime') WHERE IP=%s",
            ("@#" + target2, target1))
        self.db_conn.commit()

    def add_deviceinfo(self, target1, target2):
        self.logger.debug("DB: add_deviceinfo %s %s" % (target1, target2))
        self.db.execute(
            "UPDATE IP SET DEVICEINFO=CONCAT(DEVICEINFO,%s),TIMESTAMP=NOW() WHERE IP=%s",
            ("@#" + target2, target1))
        self.db_conn.commit()

    def add_protocol(self, target1, target2, target3):
        self.logger.debug("DB: add_protocol %s %s %s" % (target1, target2, target3))
        self.db.execute(
            "UPDATE SERVICES SET PROTOCOL=CONCAT(PROTOCOL,%s),TIMESTAMP=NOW() WHERE IP=%s and PORT=%s",
            ("@#" + target3, target1, target2))
        self.db_conn.commit()

    def add_service_app(self, target1, target2, target3):
        self.logger.debug("DB: add_service_app %s %s %s" % (target1, target2, target3))
        self.db.execute(
            "UPDATE SERVICES SET SERVICE_APP=CONCAT(SERVICE_APP,%s),TIMESTAMP=NOW() WHERE IP=%s and PORT=%s",
            ("@#" + target3, target1, target2))
        self.db_conn.commit()

    def update_ip_scan_timestamp(self, target1, target2):
        self.logger.debug("DB: update_ip_scan_timestamp %s %s" % (target1, target2))
        self.db.execute(
            "UPDATE SCAN SET METHOD=CONCAT(METHOD,%s),TIMESTAMP=NOW() WHERE IP=%s",
            ("@#" + target1, target2))
        self.db_conn.commit()

    def update_ip_port_timestamp(self, target1, target2):
        self.logger.debug("DB: update_ip_port_timestamp %s %s" % (target1, target2))
        self.db.execute(
            "UPDATE IP SET METHOD=CONCAT(METHOD,%s),TIMESTAMP=NOW() WHERE IP=%s",
            ("@#" + target1, target2))
        self.db_conn.commit()

    def update_ip_services_timestamp(self, target1, target2, target3):
        self.logger.debug("DB: update_ip_services_timestamp %s %s %s" % (target1, target2, target3))
        self.db.execute(
            "UPDATE SERVICES SET METHOD=CONCAT(METHOD,%s),TIMESTAMP=NOW() WHERE IP=%s and PORT=%s",
            ("@#" + target1, target2, target3))
        self.db_conn.commit()

    def get_all_ip(self):
        self.logger.debug("DB: get_all_ip")
        self.db.execute("SELECT IP FROM IP")
        self.db_conn.commit()
        cursor = self.db.fetchall()
        try:
            return [i['IP'] for i in cursor]
        except Exception:
            return None

    def get_service_from_ip(self,target):
        # todo: 查询出端口，协议，service_app
        port = ''
        protocol = ''
        service_app = ''
        return port, protocol, service_app

    def get_deviceinfo_from_ip(self,target):
        self.logger.debug("DB: get_deviceinfo_from_ip %s" % (target,))
        self.db.execute("SELECT DEVICEINFO FROM IP where IP=%s",(target,))
        self.db_conn.commit()
        i = self.db.fetchone()
        try:
            return i['DEVICEINFO']
        except Exception:
            return None

    def get_honeypot_from_ip(self,target):
        self.logger.debug("DB: get_honeypot_from_ip %s" % (target,))
        self.db.execute("SELECT HONEYPOT FROM IP where IP=%s",(target,))
        self.db_conn.commit()
        i = self.db.fetchone()
        try:
            return i['HONEYPOT']
        except Exception:
            return None
    def get_timestamp_from_ip(self,target):
        self.logger.debug("DB: get_timestamp_from_ip %s" % (target,))
        self.db.execute("SELECT TIMESTAMP FROM IP where IP=%s",(target,))
        self.db_conn.commit()
        i = self.db.fetchone()
        try:
            return i['TIMESTAMP']
        except Exception:
            return None