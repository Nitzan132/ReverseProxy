from socket import socket
import classes
from concurrent.futures import ThreadPoolExecutor
import FilterDevice
import logging

buffer_size = 4096
max_conn = 10 # for now

logging.basicConfig(filename="proxy.log",format='%(asctime)s %(message)s',filemode='w') 
log = logging.getLogger()

target_url = 'en.wikipedia.org'
host = "localhost" # get this as argument while setting 
port = 8080 # get this as argument while setting


def parse_headers(packet) :
    """
    Background: This function parse the packet headers so we can change them if we needed to do so.
    Arguments: the only argument is the packet that get parsed. 
    Return: return the headers in dictionary in this type => Header_Name : Header_content
    """
    req_header = {}
    for line in packet.split('\n') :# split the packet to lines
        line_parts = [o.strip() for o in line.split(':', 1)]# split to header name and value=> (Host, en.wikipedia.org)
        if len(line_parts) == 2 : # if their name and value it put inside the headers dictionary
            req_header[line_parts[0]] = line_parts[1]
    return req_header


def get_headers_string(headers):
    """
    Background: This function create string from given dictionary so we can add it to the response packet 
    Arguments: The headers dictionary
    Return: string of headers in this way => "Host: en.wikipedia.org"
    """
    header_list = ''
    for i in headers.keys():
        header_list +=   i + ' : '+ headers[i] + '\n'
    return header_list

def build_response_message(response):
    """
    Background: 
    Arguments:
    Return:
    """
    response_packet = 'HTTP/1.1'
    return response_packet + " " + str(response.status_code) + " " + classes.responses_code[response.status_code] + \
           '\n' + get_headers_string(response.headers) + " " + response.text

def edit_packet(message):
    """
    Background: 
    Arguments:
    Return:
    """
    try:
        path = (message.split("\n")[0]).split()[1]
        url = 'https://{}{}'.format( target_url, path)

        header_params = parse_headers('\n'.join(message.split('\n')[1 :]))
        header_params['Host'] = '{}:{}'.format(host,port)
        return url , header_params
    except IndexError as e:
        log.error('Error:\n{}'.format(e))
        exit(0)

def do_GET(packet) :
    """
    Background: 
    Arguments:
    Return:
    """
    url , header_params = edit_packet(packet.get_content())
    try:
        req = classes.requests.get(url=url,headers=header_params)
    except ConnectionError as e:
        log.error('Error:\n{}'.format(e))
        exit(0)
    return build_response_message(req)


def do_POST(packet) :
    """
    Background: 
    Arguments:
    Return:
    """
    packet_split = packet.get_content().split("\n\n")[0]
    url , header_params = edit_packet(packet_split)
    data_section = packet_split[1]    

    try:
        req = classes.requests.post(url=url,headers=header_params,data=data_section)
    except ConnectionError as e:
        log.error('Error:\n{}'.format(e))
        exit(0)
    return build_response_message(req)

def do_SEND(packet):
    """
    Background: 
    Arguments:
    Return:
    """
    url , header_params = edit_packet(packet.get_content())
    try:
        req = classes.requests.get(url=url,headers=header_params)
    except  ConnectionError as e:
        log.error('Error:\n{}'.format(e))
        exit(0)
    return build_response_message(req)
 
def http_functions(packet):
    """
    This function take the first line of request and direct the packet to the right place for it. 
    for instant: POST /cgi-bin/process.cgi HTTP/1.1 -> The fucntion send the packet to the POST handle method.
    The arguments are s , packet ,addr => s = socket info, packet = the packet that the proxy recived, addr = (Ip and Port) of recived packet.  
    The function return the response the target website returned.
    """
    http_functions_dict   = {'GET' : do_GET, 'POST' : do_POST, 'SEND' : do_SEND}
    http_method = packet.get_content().split('\n')[0].split(' ')[0]
    if http_method in ['GET' , 'HEAD', 'POST']:
        if http_method =='HEAD':
            http_method = 'GET'
        return http_functions_dict[http_method](packet)
    else :
        return http_functions_dict['SEND'](packet)

def proxy(sock, info) :
    """
    Background:
    Arguments:
    Return:
    """
    addr, db_pointer = info[0] , info[1]
    try :
        while True:
            data =sock.recv(buffer_size).decode()
            print(data)
            
            packet = classes.packet_information(sock,data,addr)
            score = FilterDevice.calc_vulnerability(data)
            if score == classes.Action.block:
                ip, src_port = sock.getpeername()
                addIp(ip)
                log.info('End of conversation with {} {} Because suspect packet.'.format(addr[0],addr[1]))
                #print('End of conversation with {} {} Because suspect packet.'.format(addr[0],addr[1]))
                break
            else:
                returned_data = http_functions(packet)
        
            if not packet :# end of conversation
                log.info('End of conversation with {} {}'.format(addr[0],addr[1]))
                break
            print(returned_data)
            sock.send(returned_data.encode())
    except ConnectionResetError :
       sock.close()
       

def addIp(ip):
    pass


def ip_filter(ip):
    """
    Background: this fuction search in the db of the ip is there if its there its block it from the proxy  
    Arguments:ip source
    Return: True if it there and False if it isn't there 
    """    
    return True


def main() :
    """
    Background: 
    Arguments:
    Return:
    """
    db = classes.DataBaseHandler.mySql_db()
    db.create_table()

    sock = classes.socket.socket(classes.socket.AF_INET, classes.socket.SOCK_STREAM)
    
    try:
        sock.bind((host, port))#error the port was busy before running
        log.info("socket binded to port {}".format(port))
    except RuntimeError as e:
        log.error("socket error in bind\n\n{}".format(e))
        exit(1)

    sock.listen(max_conn)  # for five connections
    log.info("socket is listening")

    
    with ThreadPoolExecutor(max_conn) as executor:
    # a forever loop until client wants to exit
        try :
            while True :
                self, addr = sock.accept()

                ip, src_port = self.getpeername()

                # lock acquired by client
                block_or_not = ip_filter(ip)
                # Start a new thread and return its identifier
                executor.submit(proxy, (self, (addr, db),))
                
                log.info('Connected to : {} : {}\nClient number: {}'.format(addr[0], addr[1]))
        finally :
            sock.close()


if __name__ == '__main__' :
    main()
