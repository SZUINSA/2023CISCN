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
        self.logger.info("Connect Sqlite Database Succeed.")
        self.logger.info("Building Mysql Database...")
        self.build()
        self.logger.info("Building Mysql Database Succeed.")
