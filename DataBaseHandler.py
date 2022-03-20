from sqlite3.dbapi2 import Error
import classes
import json
import sqlite3
import mysql.connector
from abc import ABC, abstractmethod
from time import time
# use ttl in the db and crete one long string in this format
# hash(IP), ENTERANCE TIME, TIME LIMIT

"""
Table == IpTable
--------------------------------------------------
|IP - STR |ENTERANCE TIME - STR | TIME_LIMIT -STR| 
--------------------------------------------------
"""

class db(ABC):
    @abstractmethod
    def __init__(self):
        pass
    @abstractmethod
    def create_table(self):
        pass
    @abstractmethod
    def insert(self,ip,time_limit):
        pass
    @abstractmethod
    def select(self,ip):
        pass
    @abstractmethod
    def send_query(self,query):
       pass
    @abstractmethod
    def close(self):
        pass
class sqlite_db(db):
    def __init__(self):
        try:
            self._conn = sqlite3.connect('project.db')
            self._cursor = self._conn.cursor()
        except sqlite3.Error as e:
            self._conn.close()
            print('Error while connecting to DB')
        
    def create_table(self):
        sql_command =r"""CREATE TABLE IpTable(IP TEXT PRIMARY KEY NOT NULL,ENTERANCE_TIME  TEXT NOT NULL, TIME_LIMIT TEXT NOT NULL)"""
        self._cursor.execute(sql_command)
        self._conn.commit()

    def insert(self,ip,time_limit):
        sql_command = r"""INSERT INTO IpTable(IP,ENTERANCE_TIME,TIME_LIMIT) VALUES ('{}','{}','{}');""".format(ip,str(time()),time_limit)
        self.send_query(sql_command)

    def select(self,ip):
        sql_command = r"""SELECT COUNT(*) FROM IpTable WHERE IP == {}""".format(ip)
        self._cursor.execute(sql_command)
        ans = self._cursor.fetchall()
        if len(ans) > 0:
            return True
        return False

    def send_query(self,query):
        try:
            self._cursor.execute(query)
            self._conn.commit()
        except sqlite3.Error as e:
            print(e ,'\n' ,query)

    def close(self):
        self._conn.close()
class mySql_db(db):
    def __init__(self):
        try:
            try:
                self._mydb = mysql.connector.connect(host="localhost",user="myusername",password="mypassword")
                self._cur = self._mydb.cursor()
                self._cur.execute("CREATE DATABASE My_DB")
            except:
                self._mydb = mysql.connector.connect(host="localhost",user="myusername",password="mypassword",database='My_DB')
                self._cur = self._mydb.cursor()
        except mysql.connector.Error as err:
            print("Something went wrong: {}".format(err))
            self.close()
            exit(1)
    
    def create_table(self):
        sql_cpmmand = r"""CREATE TABLE IpTable(IP TEXT PRIMARY KEY NOT NULL,ENTERANCE_TIME  TEXT NOT NULL, TIME_LIMIT TEXT NOT NULL)"""
        self._cur.execute(sql_cpmmand)
        self._mydb.commit()
    
    def insert(self, ip, time_limit):
        sql_command = r"""INSERT INTO IpTable (IP, ENTERANCE_TIME ,TIME_LIMIT) VALUES (%s, %s ,%s)""" % (ip,str(time()),time )
        self._cur.execute(sql_command)
        self._mydb.commit()
    
    def select(self,ip):
        sql_command = r"""SELECT COUNT(*) FROM IpTable WHERE IP == {}""".format(ip)
        self._cur.execute(sql_command)
        ans = self._cur.fetchall()
        if len(ans) > 0:
            return True
        return False

    def send_query(self, query):
        pass    
    def close(self):
        self._mydb.close()

mydb = mysql.connector.connect(
  host="localhost",
  user="yourusername",
  password="yourpassword"
)

print(mydb)
