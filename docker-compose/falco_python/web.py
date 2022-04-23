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


#TODO: Nginx有時候會不寫log


isolate_ip_set = set()
honeypot_ip_set = set()

@app.route('/', methods=['GET', 'POST']) 
def index():
    if request.method == 'POST': 
        data = request.get_json()
        # 開啟檔案
        fp = open("falco.log", "a")
        
        # 把falco傳過來的message寫入到檔案
        fp.write(json.dumps(data)+"\n")

        fp.close()
        app.logger.info(json.dumps(data))

        #如果是honeypotcontainer觸發的事件就不要管他
        if str(data['output_fields']['container.name']) in ['castle-honeypot']:
            # app.logger.info(str(data['output_fields']['container.name']))
            app.logger.info('Event happened in honeypot application container, ignore it.')
            return 'resolve'

        #解析Falco傳過來的資訊（process PID, 時間戳記）
        falco_process_id = str(data['output_fields']['proc.ppid'])
        falco_time_stp = datetime.fromisoformat(str(data['time'][:26])) + timedelta(hours=8) #改成UTC+8
        falco_container_ip = get_container_ip(str(data['output_fields']['container.name']))

        abnormal_ip = search_from_nginx_log(falco_process_id, falco_time_stp, falco_container_ip)
        app.logger.info(abnormal_ip)

        if abnormal_ip:
            #寫入Nginx設定檔，並且reload Nginx設定，讓惡意IP的流量被分流
            insert_ip(abnormal_ip, 'honeypot')
            reload_nginx()
            return 'Hello POST'

    return "Hello"

def fast_search_position_in_file(fd, target_string):
    mm = mmap.mmap(fd.fileno(), 0, prot=mmap.PROT_READ)
    regex_result = re.search(bytes(target_string, 'ascii'), mm)
    if regex_result == None:
        print('Not found')
        return -1
    return regex_result.start()

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

    honeypot_ip = get_container_ip('castle-honeypot')

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


        if (upstream_ip != honeypot_ip) and (upstream_ip == falco_container_ip) and (source_ip not in real_ip_list) and time_in_range(msec_datetime - timedelta(seconds=upstream_response_time), msec_datetime, falco_time_stp):
            app.logger.info(line)
            real_ip_list.append(source_ip)

    app.logger.info(real_ip_list)

    if len(real_ip_list) == 1 and ((str(real_ip_list[0])+"/32") in isolate_ip_set):
        #如果發現的唯一一個IP是先前有被隔離的，那就 1.把他導向honeypot，並且2. 其餘同一梯次的隔離夥伴就解除隔離


        # 其餘IP解除隔離
        temp_ip_set = set()
        temp_ip_set.add(real_ip_list[0]+"/32")
        isolated_ip_difference_list = list(isolate_ip_set - temp_ip_set )

        for ip_addr in isolated_ip_difference_list:
            edit_ip(str(ip_addr), 'app_lb')
            isolate_ip_set.remove(ip_addr)
            app.logger.info('解除隔離：'+str(ip_addr))

        #把他導向honeypot，並從隔離名單中刪除
        edit_ip(str(real_ip_list[0])+'/32', 'honeypot')
        isolate_ip_set.remove(str(real_ip_list[0])+"/32")
        honeypot_ip_set.add(str(real_ip_list[0])+"/32")
        
        reload_nginx()
        return False

    elif len(real_ip_list) > 1: #如果同時發現2個（或以上）的IP。分兩種情況：1. 兩個都是普通IP; 2. 兩個都是被隔離的IP
        app.logger.info("find more than 1 IP in log: " + str(real_ip_list))
        real_ip_list = [i+"/32" for i in real_ip_list]
    
        #解除其他隔離IP，並讓原本沒有被隔離的IP加入隔離區

        # 在隔離名單，但不在重疊名單的IP。將他解除隔離
        for element in list( isolate_ip_set - set(real_ip_list) ):
            edit_ip(str(element), 'app_lb')
            isolate_ip_set.remove(str(element))

        # 在重疊名單，但不在隔離名單。將他加進隔離區
        for element in list(set(real_ip_list) - isolate_ip_set):
            insert_ip(str(element), 'isolate')
            isolate_ip_set.add(str(element))
            app.logger.info("新增隔離: "+str(element))
        reload_nginx() #這邊reload也可以把重新分配IP hash的load balance規則，避免下次相同的IP又壯再一起
        return False
    elif len(real_ip_list) < 1: #沒有在log中找到這筆記錄，代表這個request已經被導向另一個Honeypot Container了
        app.logger.info("Activity not found in log file")
        return False

    return real_ip_list[0]

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
    container = docker_client.containers.get(container_name)
    ip_add = container.attrs['NetworkSettings']['Networks'][network_name]['IPAddress']
    return ip_add

def parse_ip_value_from_conf(ip_value):
    global NGINX_CONF_PATH
    org_conf = parse_nginx_conf()

    isolate_ip_set = set()
    for element in org_conf[0][1]:
        if element[1] == str(ip_value):
            isolate_ip_set.add(element[0])
    
    return isolate_ip_set

@app.route('/show', methods=['GET']) 
def show():
    global isolate_ip_set, honeypot_ip_set
    return "isolate_ip_set: "+str(isolate_ip_set) + " honeypot_ip_set: "+str(honeypot_ip_set)

if __name__ == '__main__':

    isolate_ip_set = parse_ip_value_from_conf("isolate")
    honeypot_ip_set = parse_ip_value_from_conf("honeypot")

    app.debug = True
    app.run(host='0.0.0.0', threaded=True, port=5000)


