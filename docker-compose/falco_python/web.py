from flask import Flask, request
import json
from nginxparser_eb import load, dumps
from datetime import datetime, timedelta
import docker
import re
import mmap

NGINX_CONF_PATH = '/nginx/develop/webshell_nginx_develop.conf'
app = Flask(__name__)
docker_client = docker.from_env()

upstream_response_time_regex = re.compile(r'\supstream_response_time=([0-9]+\.[0-9]{3})\s')
msec_regex = re.compile(r'\smsec=([0-9]{10}\.[0-9]{3})\s')
source_ip_regex = re.compile(r'\sremote_addr=((?:[0-9]{1,3}\.){1,3}[0-9]{1,3})\s')
upstream_ip_regex = re.compile(r'\supstream_addr=((?:[0-9]{1,3}\.){1,3}[0-9]{1,3})[: 0-9]{0,6}\s')

# nien-yun
honeypot_container_regex = re.compile(r'\webshell_php5_demo_honeypot_(\d{1,4})')


#TODO: Nginx有時候會不寫log


isolate_ip_set = set()
honeypot_ip_set = set()     #儲存honeypot的IP的CIDR表示法(例如: '192.168.88.222/32')

#global active?
ACTIVE_DYMANIC_HONEYPOT = False

@app.route('/', methods=['GET', 'POST']) 
def index():
    global ACTIVE_DYMANIC_HONEYPOT

    if request.method == 'POST': 
        data = request.get_json()
        # 開啟檔案
        fp = open("falco.log", "a")
        
        # 把falco傳過來的message寫入到檔案
        fp.write(json.dumps(data)+"\n")

        fp.close()
        app.logger.info(json.dumps(data))

        if any(key not in data for key in ['output', 'tags']) or any(key not in data['tags'] for key in ['container']):
            return 'ignore'

        #如果是honeypotcontainer觸發的事件就不要管他
        #nien-yun
        if ACTIVE_DYMANIC_HONEYPOT:
            max_hoenypot = check_scale_max_number()
            for i in range(1, max_hoenypot):
                ignore_container = 'webshell_php5_demo_honeypot_' + str(i)

                if str(data['output_fields']['container.name']) in [ignore_container]:
                    # app.logger.info(str(data['output_fields']['container.name']))
                    app.logger.info('Event happened in honeypot application container, ignore it.')
                    return 'resolve'
        else:
            if str(data['output_fields']['container.name']) in ['castle-honeypot']:
                # app.logger.info(str(data['output_fields']['container.name']))
                app.logger.info('Event happened in honeypot application container, ignore it.')
                return 'resolve'

        #解析Falco傳過來的資訊（process PID, 時間戳記, 出問題的container IP）
        falco_process_id = str(data['output_fields']['proc.ppid'])
        falco_time_stp = datetime.fromisoformat(str(data['time'][:26])) + timedelta(hours=8) #改成UTC+8
        falco_container_ip = get_container_ip(str(data['output_fields']['container.name']))

        attacker_ip_list = search_from_nginx_log(falco_process_id, falco_time_stp, falco_container_ip)
        app.logger.info("attacker_ip_list: "+str(attacker_ip_list))

        if len(attacker_ip_list)>1:
            multiple_abnormal_IP(attacker_ip_list)
        elif len(attacker_ip_list)==1:
            single_attacker_IP(attacker_ip_list)
        else:
            app.logger.info("Activity not found in log file")

    return "Hello"

def fast_search_position_in_file(fd, target_string):
    mm = mmap.mmap(fd.fileno(), 0, prot=mmap.PROT_READ)
    regex_result = re.search(bytes(target_string, 'ascii'), mm)
    if regex_result == None:
        print('Not found')
        return -1
    return regex_result.start()

def ip_in_isolate_list(ip_addr):
    global isolate_ip_set
    return (str(ip_addr)+"/32") in isolate_ip_set


def single_attacker_IP(attacker_ip_list):
    global isolate_ip_set

    attacker_IP = attacker_ip_list[0]

    # 抓到的這個IP是隔離中的IP
    if ip_in_isolate_list(attacker_IP):
        #如果發現的唯一一個IP是先前有被隔離的，那就 1.把他導向honeypot，並且2. 其餘隔離IP就解除隔離

        # 全部IP解除隔離
        for ip_addr in list(isolate_ip_set):
            ip_addr = ip_addr.replace("/32","")
            remove_ip_from_isolate(ip_addr)

    add_ip_to_honeypot(attacker_IP)
    reload_nginx()

    

def add_ip_to_honeypot(ip_addr):
    global honeypot_ip_set
    global ACTIVE_DYMANIC_HONEYPOT

    insert_ip(str(ip_addr)+'/32', 'honeypot')

    #確認IP沒有重複之後才開啟scale的honeypot
    check_ip_str = str(ip_addr) + "/32"
    if check_ip_str not in honeypot_ip_set:
        if ACTIVE_DYMANIC_HONEYPOT:
            number = get_next_honeypot_number()
            if number > 0:
                insert_honeypot_to_nginx(number)
                start_honeypot(number)
    
    honeypot_ip_set.add(str(ip_addr)+"/32")
    
    app.logger.info("新增Honeypot: "+str(ip_addr))



def add_ip_to_isolate(ip_addr):
    global isolate_ip_set
    insert_ip(str(ip_addr)+'/32', 'isolate') # 將他加進隔離區
    isolate_ip_set.add(str(ip_addr)+'/32') # 將他加進隔離名單
    app.logger.info("新增隔離: "+str(ip_addr))

def remove_ip_from_isolate(ip_addr):
    global isolate_ip_set
    edit_ip(str(ip_addr)+'/32', 'app_lb') # 將他解除隔離
    isolate_ip_set.remove(str(ip_addr)+'/32') # 從隔離名單中移除
    app.logger.info("解除隔離: "+str(ip_addr))

def multiple_abnormal_IP(abnormal_IP_list):
    global isolate_ip_set

    abnormal_IP_list = [i+"/32" for i in abnormal_IP_list]

    if len(abnormal_IP_list) > 1: #如果同時發現2個（或以上）的IP。分兩種情況：1. 兩個都是普通IP; 2. 兩個都是被隔離的IP
        app.logger.info("find more than 1 IP in log: " + str(abnormal_IP_list))
    
        #解除其他隔離IP，並讓原本沒有被隔離的IP加入隔離區

        # 在隔離名單，但不在重疊名單的IP。將他解除隔離
        for element in list( isolate_ip_set - set(abnormal_IP_list) ):
            element = element.replace("/32","")
            remove_ip_from_isolate(element)

        # 在重疊名單，但不在隔離名單。將他加進隔離區
        for element in list(set(abnormal_IP_list) - isolate_ip_set):
            element = element.replace("/32","")
            add_ip_to_isolate(element)
        reload_nginx() #這邊reload也可以把重新分配IP hash的load balance規則，避免下次相同的IP又撞在一起
    else:
        app.logger.info('abnormal_IP_list has less than 2 IP')


# 從Nginx log裡面找出攻擊者的IP
def search_from_nginx_log(falco_process_id, falco_time_stp, falco_container_ip):
    global isolate_event_id, isolate_ip_set
    nginx_log_fd = open('/nginx/nginx_log/access.log',"r")

    position_result = fast_search_position_in_file(nginx_log_fd, re.escape(falco_time_stp.strftime("[%d/%b/%Y:%H:%M:")))

    #如果有找到時間戳記，可以快速定位到指定的行數
    if position_result != -1:
        app.logger.info("fast seek to certain line")
        nginx_log_fd.seek(position_result)
    lines = nginx_log_fd.readlines()
    nginx_log_fd.close()


    real_ip_list = []

    # 提早結束條件：30秒以前的Nginx log直接忽略、超過現在時間的Nginx log之後都忽略不看（直接break）
    from_time_condition = datetime.now() - timedelta(seconds=15)
    end_time_condition = datetime.now()
    
    for line in  lines:
        # 有時候Nginx的log會少打字上去
        try:
            msec = msec_regex.search(line).group(1)
            msec_datetime = datetime.fromtimestamp(float(msec))


            # 提早結束條件
            if msec_datetime < from_time_condition:
                continue
            elif msec_datetime > end_time_condition:
                break

            upstream_response_time = float(upstream_response_time_regex.search(line).group(1))
            source_ip = source_ip_regex.search(line).group(1)
            upstream_ip = upstream_ip_regex.search(line).group(1)
        except Exception as e:
            app.logger.info(e)
            app.logger.info("錯誤")
            app.logger.info(line)
            continue


        if (upstream_ip == falco_container_ip) and (source_ip not in real_ip_list) and time_in_range(msec_datetime - timedelta(seconds=upstream_response_time), msec_datetime, falco_time_stp):
            app.logger.info(line)
            real_ip_list.append(source_ip)

    app.logger.info(real_ip_list)

    return real_ip_list

def parse_nginx_conf():
    global NGINX_CONF_PATH
    org_conf_fp = open(NGINX_CONF_PATH,"r")

    org_conf = load(org_conf_fp)
    org_conf_fp.close()

    return org_conf


def insert_ip(ip, value):
    global NGINX_CONF_PATH
    org_conf = parse_nginx_conf()

    if check_duplicated_ip(org_conf[0][1], ip): 
        insert_ip_element = ['\t'+ip+'\t', str(value)]
        org_conf[0][1].append(insert_ip_element)
        org_conf[0][1].append(['\n'])

        fp = open(NGINX_CONF_PATH,"w")
        fp.write(dumps(org_conf))
        fp.close()
    else:
        # 如果相同的IP有重複，那就直接用edit去改值
        edit_ip(ip, value)
        

# 修改Nginx設定檔中的geo值（因為nginxparser_eb沒有實作list的pop()或remove()....QQ，只好用更改的）
def edit_ip(ip, new_value):
    global NGINX_CONF_PATH
    org_conf = parse_nginx_conf()
    target_index = -1

    for index, element in enumerate(org_conf[0][1]):
        if element[0] == str(ip) or element[0] == (str(ip)):
            target_index = index
            break

    if target_index > -1:
        app.logger.info('Edit the value of IP '+str(ip)+' from '+str(org_conf[0][1][target_index][1])+' to '+str(new_value))
        org_conf[0][1][target_index] = ['\n\t'+str(ip)+'\t', str(new_value)]
        fp = open(NGINX_CONF_PATH,"w")
        fp.write(dumps(org_conf))
        fp.close()
    else:
        app.logger.info('Not found IP in nginx conf file: '+str(ip))

#檢查IP是否已經重複新增的Nginx設定檔裡面了
def check_duplicated_ip(ip_list, new_ip):
    for element in ip_list:
        if element[0] == new_ip:
            app.logger.info("Duplicated IP : "+ new_ip)
            return False
    return True

#裡面Python的Docker套件來對Nginx的Container執行reload命令
def reload_nginx():
    nginx_container = docker_client.containers.get('castle-nginx')
    app.logger.info("start reload_nginx")
    nginx_container.exec_run('sh -c "nginx -s reload"')
    app.logger.info("end reload_nginx")

def time_in_range(start, end, x):
    """Return true if x is in the range [start, end]"""
    if start <= end:
        return start <= x <= end
    else:
        return start <= x or x <= end

def get_container_ip(container_name):
    network_name = "webshell_php5_demo_castle-network"
    
    if check_container_exist(container_name):
        container = docker_client.containers.get(container_name)
        ip_add = container.attrs['NetworkSettings']['Networks'][network_name]['IPAddress']
        return ip_add
    else:
        app.logger.info('cannot get container: ' + container_name)


    

def parse_ip_value_from_conf(ip_value):
    global NGINX_CONF_PATH
    org_conf = parse_nginx_conf()

    isolate_ip_set = set()
    for element in org_conf[0][1]:
        if element[1] == str(ip_value):
            isolate_ip_set.add(element[0])
    
    return isolate_ip_set

#檢查nginx設定黨裡面有沒有重複的honeypot server名稱
def check_duplicated_honeypot(honeypot_list, new_honeypot_no):
    for element in honeypot_list:
        tempt = honeypot_container_regex.match( str(element[1]) )
        if tempt:
            temp = tempt.group(1)
        else:
            temp = 0

        if int(temp) == int(new_honeypot_no):
            app.logger.info("Duplicated honeypot number : " + str(new_honeypot_no))
            return False
    return True

#將新增的honeypot server加入nginx設定檔,value是指scale後的container id後綴
def insert_honeypot_to_nginx(value):
    global NGINX_CONF_PATH
    org_conf = parse_nginx_conf()

    if check_duplicated_honeypot(org_conf[3][1], value):

        insert_ip_element = ['\tserver\t', 'webshell_php5_demo_honeypot_' + str(value) + ':9000']
        org_conf[3][1].append(insert_ip_element)
        org_conf[3][1].append(['\n'])

        fp = open(NGINX_CONF_PATH,"w")
        fp.write(dumps(org_conf))
        fp.close()
    else:
        app.logger.info("insert honeypot number " + str(value) + " duplicated")



#檢查container是否存在,若不存在docker sdk會報錯
def check_container_exist(conatiner_name):
    container_list = docker_client.containers.list(all=True)
    for container in container_list:
        if str(container.name) == conatiner_name:
            return True

    return False

#用docker ps -a來取得scale的最大值
def check_scale_max_number():
    max_num = 0
    container_list = docker_client.containers.list(all=True)

    for container in container_list:
        re_result = honeypot_container_regex.match(str(container.name))

        if re_result:
            if int(max_num) < int(re_result.group(1)):
                max_num = int(re_result.group(1))
    
    return max_num

# initial時把scale多出來的honeypot容器暫停
def stop_all_honeypot():
    global honeypot_container_regex

    for i in range(check_scale_max_number(), 1, -1):
        stop_name = 'webshell_php5_demo_honeypot_' + str(i)
        stop_container = docker_client.containers.get(stop_name)
        if stop_container:
            if str(stop_container.status) != 'stop':
                stop_container.stop()
            else:
                app.logger.info(stop_name + " is already stop")
            
        else:
            app.logger.info(stop_name + " container not found")

#用docker ps來確定現在開到第幾個scale的honeypot,回傳下一個可用的scale number,若已經開到上限,則回傳-1
def get_next_honeypot_number():
    next_num = 0
    container_list = docker_client.containers.list()

    for container in container_list:
        re_result = honeypot_container_regex.match(str(container.name))

        if re_result:
            if int(next_num) < int(re_result.group(1)):
                next_num = int(re_result.group(1))
    
    if (next_num + 1) > check_scale_max_number():
        app.logger.info("no more honeypot can start")
        return -1
    else:
        return next_num + 1

#使後綴是number的honeypot container start
def start_honeypot(number):
    start_name = 'webshell_php5_demo_honeypot_' + str(number)

    if check_container_exist(start_name):
        start_container = docker_client.containers.get(start_name)

        if start_container:
            if str(start_container.status) != 'running':
                #maybe restart better?
                start_container.start()
            else:
                app.logger.info(start_name + " is already running")
    else:
        app.logger.info("starting " + start_name + " container not found")

# 將沒有開啟動態honeypot的所有scale container加入nginx
def scale_honeypot_addto_nginx():
    max_num = check_scale_max_number()

    for i in range(2, max_num + 1):
        insert_honeypot_to_nginx(i)


@app.route('/show', methods=['GET']) 
def show():
    global isolate_ip_set, honeypot_ip_set
    return "isolate_ip_set: "+str(isolate_ip_set) + " honeypot_ip_set: "+str(honeypot_ip_set)

if __name__ == '__main__':

    isolate_ip_set = parse_ip_value_from_conf("isolate")
    honeypot_ip_set = parse_ip_value_from_conf("honeypot")

    if ACTIVE_DYMANIC_HONEYPOT:
        app.logger.info("active?")
        stop_all_honeypot()
    else:
        scale_honeypot_addto_nginx()


    app.debug = True
    app.run(host='0.0.0.0', threaded=True, port=5000)


