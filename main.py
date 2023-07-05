import sys
import logging


def logs(filename='logs.txt', level=logging.DEBUG):
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    fh = logging.FileHandler(filename)
    fh.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    formatter = logging.Formatter(
        "[%(asctime)s]\t[%(thread)d]\t[%(filename)s]\t[line: %(lineno)d]\t[%(levelname)s]\t#%(message)s")
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


if __name__ == "__main__":
    logger = logs()
    logger.info("Program Start")
    argv = [x.lower() for x in sys.argv]
    if "--mysql" in argv or "-m" in argv:
        logger.debug("Database: Mysql")
        import mysql

        db = mysql.db(logger)
    else:
        logger.debug("Database: Sqlite")
        import sqlite

        db = sqlite.db(logger)

    if "--scan" in argv or "-s" in argv:
        logger.debug("SCAN Mode")
        import scan

        if "scan-xxxx" in argv:
            app = scan.app(db, logger,method="sacn-xxxx")
        else:
            app = scan.app(db, logger)

    app.run()
