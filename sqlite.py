import os
import sqlite3
class db:
    def __init__(self,logger):
        self.logger=logger
        if(os.path.exists('sqlite.db')==False):
            self.db = sqlite3.connect('sqlite.db')
            self.logger.info("Building Sqlite Database...")
            self.build()
            self.logger.info("Building Sqlite Database Succeed.")
        else:
            self.db = sqlite3.connect('sqlite.db')
            self.logger.info("Connect Sqlite Database Succeed.")
        self.db.execute('PRAGMA temp_store=MEMORY;')
        self.db.execute('PRAGMA journal_mode=MEMORY;')
        self.db.execute('PRAGMA auto_vacuum=INCREMENTAL;')
    def build(self):
        self.db.execute('''CREATE TABLE IF NOT EXISTS SCAN(
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    IP TEXT NULL,
                    TIMESTAMP TIME NULL
                    );''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS IP(
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    IP TEXT NULL,
                    DEVICEINFO TEXT NULL,
                    HONEYPOT TEXT NULL,
                    TIMESTAMP TIME NULL
                    );''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS SERVICES(
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    IP TEXT NULL,
                    PORT TEXT NULL,
                    PROTOCOL TEXT NULL,
                    SERVICE_APP TEXT NULL,
                    TIMESTAMP TIME NULL
                    );''')
        self.db.commit()
    def add_scan(self, target):
        self.logger.debug("DB: add_scan %s"%(target,))
        self.db.execute("INSERT INTO SCAN (IP) VALUES (?)", (target,))
        self.db.commit()
    def add_ip(self, target):
        self.logger.debug("DB: add_ip %s"%(target,))
        self.db.execute("INSERT INTO IP (IP) VALUES (?)", (target,))
        self.db.commit()
    def get_ip_no_scan(self):
        self.logger.debug("DB: get_ip_no_scan")
        cursor = self.db.execute("SELECT IP from SCAN WHERE TIMESTAMP IS NULL LIMIT 1")
        for i in cursor:
            return i[0]
    def update_ip_scan_timestamp(self,target):
        self.logger.debug("DB: update_ip_scan_timestamp %s"%(target,))
        cursor = self.db.execute("UPDATE SCAN SET TIMESTAMP=DATETIME(CURRENT_TIMESTAMP,'localtime') WHERE IP=?",(target,))
        self.db.commit()
