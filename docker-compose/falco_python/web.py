from flask import Flask, request
import json
from nginxparser_eb import load, dumps
from datetime import datetime, timedelta
import docker
import re

app = Flask(__name__)
docker_client = docker.from_env()

upstream_response_time_regex = re.compile(r'\supstream_response_time=([0-9]+\.[0-9]{3})\s')
msec_regex = re.compile(r'\smsec=([0-9]{10}\.[0-9]{3})\s')
source_ip_regex = re.compile(r'\sremote_addr=((?:[0-9]{1,3}\.){1,3}[0-9]{1,3})\s')
upstream_ip_regex = re.compile(r'\supstream_addr=((?:[0-9]{1,3}\.){1,3}[0-9]{1,3})[: 0-9]{0,6}\s')


#TODO: Nginx有時候會不寫log


@app.route('/', methods=['GET', 'POST']) 
def index():
    if request.method == 'POST': 
        data = request.get_json()
        # 開啟檔案
        fp = open("falco.log", "a")
        
        # 把falco傳過來的message寫入到檔案
        fp.write(json.dumps(data)+"\n")

        fp.close()
        #app.logger.info(json.dumps(data))

        #解析Falco傳過來的資訊（process PID, 時間戳記）
        falco_process_id = str(data['output_fields']['proc.ppid'])
        falco_time_stp = datetime.fromisoformat(str(data['time'][:26])) + timedelta(hours=8) #改成UTC+8
        falco_container_ip = get_container_ip(str(data['output_fields']['container.name']))

        # abnormal_ip = search_from_php_log(falco_process_id, falco_time_stp.replace(microsecond=0)) #因為PHP-fpm的log時間精度只到『秒』，所以要把millisecond拿掉
        abnormal_ip = search_from_nginx_log(falco_process_id, falco_time_stp, falco_container_ip)
        app.logger.info(abnormal_ip)

        if abnormal_ip:
            #寫入Nginx設定檔，並且reload Nginx設定，讓惡意IP的流量被分流
            insert_ip(abnormal_ip+"/32")
            return 'Hello POST'
        else:
            app.logger.info(json.dumps(data))

    return "Hello"

def search_from_php_log(falco_process_id, falco_time_stp):
        #讀取PHP-fpm的log檔案
        php_fpm_log_fp = open('/php-fpm/php-fpm.access.log',"r")
        lines = php_fpm_log_fp.readlines()
        php_fpm_log_fp.close()


        #利用process ID跟時間戳記比對出行為異常的IP
        target_lines = []
        real_ip_list = []
        for line in  lines:
            if (line not in target_lines) and (json.loads(line)['real_ip'] not in real_ip_list) and (json.loads(line)['process_id']==falco_process_id) and (falco_time_stp == datetime.strptime(json.loads(line)['time'][:20], '%d/%b/%Y:%H:%M:%S')):
                real_ip_list.append(json.loads(line)['real_ip'])
                target_lines.append(line)


        if len(target_lines) > 1: #TODO: 有可能同一秒鐘有request被同一個process服務，造成紀錄完全一樣嗎？
            app.logger.info("Error: find more than 1 line log")
        
            app.logger.info(str(target_lines))
        return False
        elif len(target_lines) < 1: #沒有在正常的PHP-fpm Container中找到這筆記錄，代表這個request已經被導向另一個Honeypot Container了
            app.logger.info("Activity not found in log file")
        return False

        #惡意的IP(or 不正常的IP)
        abnormal_ip = str(json.loads(target_lines[0])['real_ip'])

    return abnormal_ip


def search_from_nginx_log(falco_process_id, falco_time_stp, falco_container_ip):
    nginx_log = open('/nginx/nginx_log/access.log',"r")
    lines = nginx_log.readlines()
    nginx_log.close()

    honeypot_ip = get_container_ip('castle-app2')

    real_ip_list = []

    # 提早結束條件：30秒以前的Nginx log直接忽略、超過現在時間的Nginx log之後都忽略不看（直接break）
    from_time_condition = datetime.now() - timedelta(seconds=30)
    end_time_condition = datetime.now()
    
    for line in  lines:
        # 有時候Nginx的log會少打字上去
        try:
            msec = msec_regex.search(line).group(1)
            msec_datetime = datetime.fromtimestamp(float(msec))


            # 提早結束條件
            if msec_datetime < from_time_condition:
                # app.logger.info("msec_datetime: "+str(msec_datetime))
                # app.logger.info("from_time_condition: "+str(from_time_condition))
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

    
    if len(real_ip_list) > 1: #TODO: 如果同時發現2個（或以上）的IP，就需要安排他們進隔離區觀察
        app.logger.info("Error: find more than 1 IP in log")
        # app.logger.info(json.dumps(data))
        app.logger.info(str(real_ip_list))
        return False
    elif len(real_ip_list) < 1: #沒有在正常的PHP-fpm Container中找到這筆記錄，代表這個request已經被導向另一個Honeypot Container了
        app.logger.info("Activity not found in log file")
        return False

    return real_ip_list[0]


def insert_ip(new_ip):
    conf_file_path = "/nginx/develop/webshell_nginx_develop.conf"
    org_conf_fp = open(conf_file_path,"r")

    org_conf = load(org_conf_fp)
    org_conf_fp.close()

    if check_duplicated_ip(org_conf[0][1], new_ip): 
        inser_ip_element = ['\t'+new_ip+'\t', '1']
        org_conf[0][1].append(inser_ip_element)
        org_conf[0][1].append(['\n'])

        fp = open(conf_file_path,"w")
        fp.write(dumps(org_conf))
        fp.close()

        reload_nginx()

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
    # print(start)
    # print(end)
    # print(x)
    if start <= end:
        return start <= x <= end
    else:
        return start <= x or x <= end

def get_container_ip(container_name):
    network_name = "webshell_php5_demo_castle-network"
    container = docker_client.containers.get(container_name)
    ip_add = container.attrs['NetworkSettings']['Networks'][network_name]['IPAddress']
    return ip_add


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', threaded=True, port=5000)


