import os


class db:
    def __init__(self, logger):
        self.logger = logger
        import sqlite3
        if not os.path.exists('sqlite.db'):
            self.logger.info("Sqlite Database Not Exist...")
            self.db = sqlite3.connect('sqlite.db')
            self.logger.info("Building Sqlite Database...")
            self.build()
            self.logger.info("Building Sqlite Database Succeed.")
        else:
            self.db = sqlite3.connect('sqlite.db')
            self.logger.info("Connect Sqlite Database Succeed.")
            self.logger.info("Building Sqlite Database...")
            self.build()
            self.logger.info("Building Sqlite Database Succeed.")
        self.db.execute('PRAGMA temp_store=MEMORY;')
        self.db.execute('PRAGMA journal_mode=MEMORY;')
        self.db.execute('PRAGMA auto_vacuum=INCREMENTAL;')

    def build(self):
        self.db.execute('''CREATE TABLE IF NOT EXISTS SCAN(
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    IP TEXT NULL,
                    METHOD TEXT DEFAULT '',
                    TIMESTAMP TIME NULL
                    );''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS IP(
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    IP TEXT NULL,
                    METHOD TEXT DEFAULT '',
                    DEVICEINFO TEXT DEFAULT '',
                    HONEYPOT TEXT DEFAULT '',
                    TIMESTAMP TIME NULL
                    );''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS SERVICES(
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    IP TEXT NULL,
                    METHOD TEXT DEFAULT '',
                    PORT TEXT NULL,
                    PROTOCOL TEXT DEFAULT '',
                    SERVICE_APP TEXT DEFAULT '',
                    TIMESTAMP TIME NULL
                    );''')
        self.db.commit()

    def add_scan(self, target):
        self.logger.debug("DB: add_scan %s" % (target,))
        cursor = self.db.execute("SELECT count() FROM SCAN WHERE IP=?", (target,))
        for i in cursor:
            if i[0] == 0:
                self.db.execute("INSERT INTO SCAN (IP) VALUES (?)", (target,))
                self.db.commit()
            else:
                self.logger.debug("DB: add_scan %s exits" % (target,))
            return

    def add_ip(self, target):
        self.logger.debug("DB: add_ip %s" % (target,))
        cursor = self.db.execute("SELECT count() FROM IP WHERE IP=?", (target,))
        for i in cursor:
            if i[0] == 0:
                self.db.execute("INSERT INTO IP (IP) VALUES (?)", (target,))
                self.db.commit()
            else:
                self.logger.debug("DB: add_ip %s exits" % (target,))
            return

    def add_services(self, target1, target2):
        self.logger.debug("DB: add_services %s %s" % (target1, target2))
        cursor = self.db.execute("SELECT count() FROM SERVICES WHERE IP=? and PORT=? ", (target1, target2))
        for i in cursor:
            if i[0] == 0:
                self.db.execute("INSERT INTO SERVICES (IP,PORT) VALUES (?,?)", (target1, target2))
                self.db.commit()
            else:
                self.logger.debug("DB: add_services %s %s exits" % (target1, target2))
            return

    def get_ip_no_scan(self, target):
        self.logger.debug("DB: get_ip_no_scan %s" % (target,))
        cursor = self.db.execute("SELECT IP from SCAN WHERE METHOD NOT LIKE ? LIMIT 1", ("%@#" + target + "%",))
        for i in cursor:
            return i[0]

    def get_ip_no_port(self, target):
        self.logger.debug("DB: get_ip_no_port %s" % (target,))
        cursor = self.db.execute("SELECT IP from IP WHERE METHOD NOT LIKE ? LIMIT 1", ("%@#" + target + "%",))
        for i in cursor:
            return i[0]

    def get_ip_no_services(self, target):
        self.logger.debug("DB: get_ip_no_services %s" % (target,))
        cursor = self.db.execute("SELECT IP,PORT from SERVICES WHERE METHOD NOT LIKE ? LIMIT 1", ("%@#" + target + "%",))
        for i in cursor:
            return i[0],i[1]

    def add_honeypot(self, target1, target2):
        self.logger.debug("DB: add_honeypot %s %s" % (target1, target2))
        cursor = self.db.execute(
            "UPDATE IP SET HONEYPOT=HONEYPOT||?,TIMESTAMP=DATETIME(CURRENT_TIMESTAMP,'localtime') WHERE IP=?",
            ("@#" + target2, target1))
        self.db.commit()

    def add_deviceinfo(self, target1, target2):
        self.logger.debug("DB: add_deviceinfo %s %s" % (target1, target2))
        cursor = self.db.execute(
            "UPDATE IP SET DEVICEINFO=DEVICEINFO||?,TIMESTAMP=DATETIME(CURRENT_TIMESTAMP,'localtime') WHERE IP=?",
            ("@#" + target2, target1))
        self.db.commit()
    def add_protocol(self, target1, target2, target3):
        self.logger.debug("DB: add_protocol %s %s %s" % (target1, target2, target3))
        cursor = self.db.execute(
            "UPDATE SERVICES SET PROTOCOL=PROTOCOL||?,TIMESTAMP=DATETIME(CURRENT_TIMESTAMP,'localtime') WHERE IP=? and PORT=?",
            ("@#" + target3, target1, target2))
        self.db.commit()

    def add_service_app(self, target1, target2, target3):
        self.logger.debug("DB: add_service_app %s %s %s" % (target1, target2, target3))
        cursor = self.db.execute(
            "UPDATE SERVICES SET SERVICE_APP=SERVICE_APP||?,TIMESTAMP=DATETIME(CURRENT_TIMESTAMP,'localtime') WHERE IP=? and PORT=?",
            ("@#" + target3, target1, target2))
        self.db.commit()



    def update_ip_scan_timestamp(self, target1, target2):
        self.logger.debug("DB: update_ip_scan_timestamp %s %s" % (target1, target2))
        cursor = self.db.execute(
            "UPDATE SCAN SET METHOD=METHOD||?,TIMESTAMP=DATETIME(CURRENT_TIMESTAMP,'localtime') WHERE IP=?",
            ("@#" + target1, target2))
        self.db.commit()

    def update_ip_port_timestamp(self, target1, target2):
        self.logger.debug("DB: update_ip_port_timestamp %s %s" % (target1, target2))
        cursor = self.db.execute(
            "UPDATE IP SET METHOD=METHOD||?,TIMESTAMP=DATETIME(CURRENT_TIMESTAMP,'localtime') WHERE IP=?",
            ("@#" + target1, target2))
        self.db.commit()

    def update_ip_services_timestamp(self, target1, target2 , target3):
        self.logger.debug("DB: update_ip_services_timestamp %s %s %s" % (target1, target2 , target3))
        cursor = self.db.execute(
            "UPDATE SERVICES SET METHOD=METHOD||?,TIMESTAMP=DATETIME(CURRENT_TIMESTAMP,'localtime') WHERE IP=? and PORT=?",
            ("@#" +target1, target2, target3))
        self.db.commit()