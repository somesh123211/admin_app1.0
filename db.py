import os
from dotenv import load_dotenv
import pymysql
import pymysql
from dbutils.pooled_db import PooledDB

print("MYSQL_HOST =", os.getenv("MYSQL_HOST"))
print("MYSQL_USER =", os.getenv("MYSQL_USER"))
print("MYSQL_PASSWORD =", os.getenv("MYSQL_PASSWORD"))
print("MYSQL_DB =", os.getenv("MYSQL_DB"))


# ------------------------------------------------------------------
# IMPORTANT:
# - load_dotenv() MUST be called at top of app.py BEFORE importing db
# ------------------------------------------------------------------

pool = PooledDB(
    creator=pymysql,
    maxconnections=2,
    mincached=0,          # 🔥 IMPORTANT (avoid startup crash)
    maxcached=2,
    blocking=True,
    host=os.getenv("MYSQL_HOST"),
    user=os.getenv("MYSQL_USER"),
    password=os.getenv("MYSQL_PASSWORD"),
    database=os.getenv("MYSQL_DB"),
    cursorclass=pymysql.cursors.DictCursor,
    autocommit=True
)


def get_db():
    """
    Returns pooled DB connection.
    .close() RETURNS connection to pool.
    """
    return pool.connection()
