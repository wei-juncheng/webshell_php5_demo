# Webshell攻擊示範專案
- 示範如何使用webshell惡意程式造成PHP網頁server的漏洞，並直接取得shell控制權。
- 本專案使用的webshell由[b374k shell 3.2](https://github.com/b374k/b374k)專案製作，適應的PHP版本為> 4.3.3 及 PHP 5
-   使用 docker-compose 進行環境管理，透過 docker compose 直接啟動 Nginx、PHP-fpm，開法者的電腦無須安裝 PHP、Nginx等等

#### 系統需求

-   已安裝並且可以運行 Docker 及 docker-compose

#### Clone 專案

`$ git clone https://github.com/wei-juncheng/webshell_php5_demo.git`

`$ cd webshell_php5_demo`

##### 建立並啟動專案：

-   `$ make build` (需要時加上 sudo)
    - 詳細指令可以參考`Makefile`的內容

##### 完成！
- 開啟瀏覽器，前往`http://localhost:8088/`，看到以下畫面表示PHP環境建置成功
    - ![](https://i.imgur.com/RaPSwCi.png)
- 開啟瀏覽器，前往`http://localhost:8088/b374k.php`即可開始體驗可怕的webshell（根目錄是這個專案的 `public/`）
    - ![](https://i.imgur.com/WPp7nNq.png)

##### 停止專案：
- `$ make down` (需要時加上 sudo)