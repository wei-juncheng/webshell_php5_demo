from flask import Flask, request
import json
from nginxparser_eb import load, dumps
from datetime import datetime, timedelta
import docker

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST']) 
def index():
    if request.method == 'POST': 
        data = request.get_json()
        # 開啟檔案
        fp = open("falco.log", "a")
        
        # 把falco傳過來的message寫入到檔案
        fp.write(json.dumps(data)+"\n")

        #解析Falco傳過來的資訊（process PID, 時間戳記）
        falco_process_id = str(data['output_fields']['proc.ppid'])
        falco_time_stp = datetime.fromisoformat(str(data['time'][:19])) + timedelta(hours=8)

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
            app.logger.info(json.dumps(data))
            app.logger.info(str(target_lines))
            return 'Error'
        elif len(target_lines) < 1: #沒有在正常的PHP-fpm Container中找到這筆記錄，代表這個request已經被導向另一個Honeypot Container了
            app.logger.info("Activity not found in log file")
            return 'dup'

        #惡意的IP(or 不正常的IP)
        abnormal_ip = str(json.loads(target_lines[0])['real_ip'])
        app.logger.info(abnormal_ip)

        #寫入Nginx設定檔，並且reload Nginx設定，讓惡意IP的流量被分流
        insert_ip(abnormal_ip+"/32")

        return 'Hello POST'

    return "Hello"

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
    client = docker.from_env()
    nginx_container = client.containers.get('castle-nginx')
    nginx_container.exec_run('sh -c "nginx -s reload"')


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', threaded=True, port=5000)


