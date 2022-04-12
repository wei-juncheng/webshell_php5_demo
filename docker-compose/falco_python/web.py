from flask import Flask, request
import json

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST']) 
def index():
    if request.method == 'POST': 
        data = request.get_json()
        # 開啟檔案
        fp = open("falco.log", "a")
        
        # 把falco傳過來的message寫入到檔案
        fp.write(json.dumps(data)+"\n")

        return 'Hello POST'

    return "Hello"

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', threaded=True, port=5000) 
    # app.run(threaded=True, port=5000) 

