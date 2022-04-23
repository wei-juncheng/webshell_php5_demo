.DEFAULT_GOAL=build

#記得要至少執行一次`make driver`安裝Falco的driver
build:
	touch ./docker-compose/php-fpm/php-fpm.access.log
	@$(MAKE) -s falco
	docker-compose --env-file .docker-compose.env up -d --build app nginx falco_python honeypot app-lb app-lb2 isolation isolation2 isolation3
	docker network connect webshell_php5_demo_castle-network falco_monitor

network:
	docker network connect webshell_php5_demo_castle-network falco_monitor

up:
	@$(MAKE) -s falco
	docker-compose --env-file .docker-compose.env up -d app nginx falco_python

down:
	docker rm -f falco_monitor
	docker-compose --env-file .docker-compose.env down

restart:
	@$(MAKE) -s clear
	@$(MAKE) -s down
	@$(MAKE) -s build

.PHONY: nginx
nginx:
	docker-compose exec nginx sh -c "nginx -s reload"

.PHONY: clear
clear:
	cp docker-compose/nginx/webshell_nginx_develop_backup.conf docker-compose/nginx/develop/webshell_nginx_develop.conf
	@$(MAKE) -s nginx

#安裝falco的kernel module，如果這步一直之敗，可以參考官網的安裝步驟：https://falco.org/docs/getting-started/installation/#debian
.PHONY: driver
driver:
	docker run --rm -i -t --privileged -v /root/.falco:/root/.falco -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro falcosecurity/falco-driver-loader:0.31.1

#啟動本地端falco當作監控工具(因為裡面有一段要直接shell script，他沒辦法在docker-compose.yml裡面執行，所以獨立出來寫成)
#設定檔放在 docker-compose/falco/ 底下
#  - 判斷system call的條件寫在falco_rule.local.yaml裡面
#  - 傳送http訊息的設定在falco.yaml檔案底下裡面的`http_output`段落
.PHONY: falco
falco:
	docker rm -f falco_monitor
	docker run -d --name falco_monitor -e HOST_ROOT=/ --cap-add SYS_PTRACE --pid=host $(shell ls /dev/falco* | xargs -I {} echo --device {}) -v /var/run/docker.sock:/var/run/docker.sock -v $(shell pwd | xargs -I {} echo {}/docker-compose/falco/falco_mount):/etc/falco falcosecurity/falco-no-driver:0.31.1


