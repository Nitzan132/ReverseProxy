import re
import socket
import requests
import threading
import os
import enum
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk import ngrams
from nltk import WordNetLemmatizer
import csv
import unicodedata 
from collections import Counter
#import DataBaseHandler
from functools import *



SQL_STOPWORDS = ['and' , 'or' , 'where', 'than'] 
DIC_OF_DATASETS =  {'xss' :  'XSS_dataset.csv', 'sql' : 'SQLiV3.csv'}

TO_RISKY = 7
NEED_TO_FOLLOW = 5

class Constants():
    def __init__(self) -> None:
        stopwords_list = stopwords.words('english')
        for i in SQL_STOPWORDS:
            stopwords_list.remove(i)


class Vulnerability(enum.Enum):
    vulnerable = 0
    suspect = 1
    innocent = 2
class Action(enum.Enum):
    block = 0   # block the IP for good
    ignore = 1  # ignore the packet because it isn't malicious
    remove = 2  # remove this speicfic packet from the stream because it's look malicious but longer chat will show it


class packet_information():
    def __init__(self,socket_info, packet_content, packet_address):
        self._socket = socket_info
        self._content = packet_content
        self._addr = packet_address
    
    def get_socket(self):
        return self._socket
    def get_address(self):
        return self._addr
    def get_content(self):
        return self._content

responses_code = {
100:"Continue"
,101:"Switching protocols"
,102:"Processing"
,103:"Early Hints"
,200:"OK"
,201:"Created"
,202:"Accepted"
,203:"Non-Authoritative Information"
,204:"No Content"
,205:"Reset Content"
,206:"Partial Content"
,207:"Multi-Status"
,208:"Already Reported"
,226:"IM Used"
,300:"Multiple Choices"
,301:"Moved Permanently"
,302:"Found (Previously 'Moved Temporarily')"
,303:"See Other"
,304:"Not Modified"
,305:"Use Proxy"
,306:"Switch Proxy"
,307:"Temporary Redirect"
,308:"Permanent Redirect"
,400:"Bad Request"
,401:"Unauthorized"
,402:"Payment Required"
,403:"Forbidden"
,404:"Not Found"
,405:"Method Not Allowed"
,406:"Not Acceptable"
,407:"Proxy Authentication Required"
,408:"Request Timeout"
,409:"Conflict"
,410:"Gone"
,411:"Length Required"
,412:"Precondition Failed"
,413:"Payload Too Large"
,414:"URI Too Long"
,415:"Unsupported Media Type"
,416:"Range Not Satisfiable"
,417:"Expectation Failed"
,418:"I'm a Teapot"
,421:"Misdirected Request"
,422:"Unprocessable Entity"
,423:"Locked"
,424:"Failed Dependency"
,425:"Too Early"
,426:"Upgrade Required"
,428:"Precondition Required"
,429:"Too Many Requests"
,431:"Request Header Fields Too Large"
,451:"Unavailable For Legal Reasons"
,500:"Internal Server Error"
,501:"Not Implemented"
,502:"Bad Gateway"
,503:"Service Unavailable"
,504:"Gateway Timeout"
,505:"HTTP Version Not Supported"
,506:"Variant Also Negotiates"
,507:"Insufficient Storage"
,508:"Loop Detected"
,510:"Not Extended"
,511:"Network Authentication Required"}
