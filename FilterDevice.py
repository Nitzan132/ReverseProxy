from cmath import atan
from time import time
import time as Time
from nltk.corpus.reader import switchboard
import classes
from nltk.corpus import wordnet
from nltk.stem import WordNetLemmatizer
import nltk
from functools import lru_cache

def headers_filtration(packet):
    """
    this functuin check the headers of packet for "wrong" parameters. 
    :return: if their fear of vulnerability to the server
    """
    regex_String = [r'(GET|POST).*\.(py|txt|html|php|js|log|xml)',r'(cmd|curl|echo)',r'(http|HTTP).*/(localhost|xxx.xxx.xxx.xxx|127.0.0.1)',r'(jndi:ldap|jndi:dns)']
    complie_regex = []
    found_loophole = []

    for regex in regex_String:
        complie_regex.append(classes.re.compile(regex, flags=classes.re.I|classes.re.M))
    
    for i in complie_regex:
        if i is not None:
            found_loophole += i.finditer(packet)
    
    if len(found_loophole) > 0:
        return classes.Vulnerability.vulnerable
    return classes.Vulnerability.innocent

def data_filtration(packet):
    """
    this functuin check the data of packet for attacks. 
    :return: if their fear of vulnerability to the server and what attack is accused of.
    """
    
    regex_String = [('sql' ,r'(WHERE | --| & | DELETE | UNION | LIKE | % | ORDER |; | 1=1 | DROP | TABLE )' ),('xss',r'((alert|on\w+|function\s+\w+)\s*\(\s*(["+\d\w](,?\s*["+\d\w]*)*)*\s*\))'),('xss',r'(script|iframe|embed|frame|frameset|object|img|body|html)')]
    complie_regex = []
    found_loophole = []
    for regex in regex_String:
        complie_regex.append((regex[0], classes.re.compile(regex[1], flags=classes.re.I|classes.re.M)))

    for i in complie_regex:
        if i[1].finditer(packet) is not None:
            if i[0] =='sql':
                return (classes.Vulnerability.suspect , 'sql')
            elif i[0] == 'xss':
                return (classes.Vulnerability.suspect , 'xss')
            else:
                pass

    return classes.Vulnerability.innocent, ''

@lru_cache(maxsize=128, typed=False)
def jacob_Similarity(suspicious_packet, n_gram):
    """
    :param suspicious_packet:
    :param n_gram:
    :param attack_name:
    :return:
    """
    a = set(suspicious_packet)
    b = set(n_gram)
    c = a.intersection(b)
    jacob = float(len(c)) / (len(a) + len(b) - len(c)) * 10
    if jacob ==0:
        return 0.000001
    return jacob

@lru_cache(maxsize=128, typed=False)
def Cosine_Similarity(suspicious_packet, n_gram) :
    """
    :param suspicious_packet:
    :param n_gram:
    :param attack_name:
    :return:
    """

    # split the sentence into single words and characters(this why I use it( because of the split to characters)).
    X_list = suspicious_packet
    Y_list = n_gram

    stopwords_list = classes.stopwords.words('english')
    
    for i in classes.SQL_STOPWORDS:
       stopwords_list.remove(i)
    
    l1 = []
    l2 = []

    # remove stop words from the string
    X_set = {word for word in X_list if not word in stopwords_list}
    Y_set = {word for word in Y_list if not word in stopwords_list}

    # form a set containing keywords of both strings
    united_vector = X_set.union(Y_set)

    for w in united_vector:
        if w in X_set:
            l1.append(1)  # create a vector
        else:
            l1.append(0)
        if w in Y_set:
            l2.append(1)  # create a vector
        else:
            l2.append(0)

    # The cosine formula
    c = 0
    for i in range(len(united_vector)):
        c += l1[i] * l2[i]
    cosine = c / float((sum(l1) * sum(l2)) ** 0.5) * 10
    return cosine

def basic_clean(line):
    sentence = classes.re.sub('( \( | \) | \, | \' )','',line[0]) 
    return sentence.split()

def create_Ngrms(attack_name,N):#create an N-gram for attack name.
    """
    create file of N-grams in given size from csv file.
    """

    with open(classes.DIC_OF_DATASETS[attack_name], 'r',encoding="utf8") as f:
        reader = classes.csv.reader(f)
        dfl = list(reader)

    string_ngrams=[]
    for line in dfl:
        if line != []:
            sentence = basic_clean(line)
            string_ngrams += [sentence[i:i+N] for i in range(len(sentence)-N+1)]
    
    Ngram_file = [] 
    with open( '{}.txt'.format(attack_name), 'a' ,encoding='utf8') as new_file:   
        for i in string_ngrams:
            new_file.write(', '.join(i) + '\n' )
            Ngram_file.append(''.join(i))
    
    most_common_Ngrams =""
    with open ('most_common_{}.txt'.format(attack_name), 'a',encoding='utf8') as most_common_file:
        ngram_counts = classes.Counter(Ngram_file)
        most_common =  ngram_counts.most_common(500)
        most_common_after_clean = []
        for i in most_common:
            most_common_Ngrams +=''.join(' '.join(i[0]).split(', '))[:-1]
            most_common_file.write("".join(i[0]))# the problem is here....
    print(most_common_Ngrams)
    return most_common_Ngrams

def get_Ngram(attack_name , N): #create an file that has the N-gram for each attack, then return list of N-grams.
    """"
    return string of N-grams if txt file os exsit otherwise it crete one and return it.
    """
    if classes.os.path.isfile('most_common_{}.txt'.format(attack_name)) == True:
        with open('most_common_{}.txt'.format(attack_name)) as f:
            return f.readlines()
    else: 
        return create_Ngrms(attack_name, N)

def get_rate_from_functions(data, attack_name,N):
    data_to_Ngram = [data[i:i+N] for i in range(len(data)-N+1)]

    attack_Ngram = get_Ngram(attack_name,N)
    #print(attack_Ngram)
    jacob = 0.1
    cosine = 0.1
    for i in data_to_Ngram:
        #print(i)
        for j in attack_Ngram: # there is a bug here with ZeroDivisionError
            try:
                if ((jacob_Similarity(j,i) + Cosine_Similarity(j,i)) /2) > ((jacob+cosine)/2 ):
                    jacob = jacob_Similarity(j,i)
                    cosine = Cosine_Similarity(j,i)
            except ZeroDivisionError as e:
                pass
    
    return ((cosine + jacob) / 2)

def split_message(packet):
    if 'POST' in packet.split('\n')[0]:
        split_parts = packet.split('\n\n')
        return (split_parts[0], split_parts[1])     
    return packet.split('\n\n')[0]

def calc_vulnerability(suspicious_packet):
    """
    """
    splited_message = split_message(suspicious_packet)
    
    if len(splited_message) > 1:
        headers , data = splited_message[0] , splited_message[1]
    else:
        headers , data = splited_message[0], None
        
    headers_risk = headers_filtration(suspicious_packet)
    if headers_risk == classes.Vulnerability.vulnerable and data ==None:
        return classes.Action.block
    elif data == None:
        return classes.Action.ignore 
       
    data_risk = data_filtration(data)  

    print('{}\n'.format(data))

    risk = 0
    if data_risk[0] == classes.Vulnerability.suspect and data != '': 
        risk  = get_rate_from_functions(data, data_risk[1],4)
        print("The risk is %s\n" % risk)
        if risk > classes.TO_RISKY:
            return classes.Action.block
        elif risk > classes.NEED_TO_FOLLOW:
            return classes.Action.remove
        return classes.Action.ignore
    
if __name__ == '__main__' :
    clean ="""POST /cgi-bin/process.cgi HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
Host: www.tutorialspoint.com
Content-Type: application/x-www-form-urlencoded
Content-Length: length
Accept-Language: en-us
Accept-Encoding: gzip, deflate
Connection: Keep-Alive

licenseID=string&content=string&/paramsXML=string"""
    dirty ="""POST /nia_munoz_monitoring_system/quiz_question.php?id=3%27%20union%20select%20NULL,NULL,NULL,NULL,NULL,@@version,NULL,NULL,NULL--%20- HTTP/1.1
Host: 111.111.111.111
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=3ptqlolbrddvef5a0k8ufb28c9
Upgrade-Insecure-Requests: 1

username=tom' order by 1 -- +&submit=Submit
"""
start = time()
print(calc_vulnerability(dirty))
end = time()
print('It take {}'.format(end - start))


#90.97
#90.76
#79.71
#3.76861834526062