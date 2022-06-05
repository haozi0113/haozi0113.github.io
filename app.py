from flask import Flask, request, render_template
import json
from socks5_client import Client
app = Flask(__name__)

@app.route('/')
def index():
    return render_template("Request.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    server = request.form.get('server')
    port = request.form.get('port')
    Client.aaa(server,port)
    return json.dumps(request.form) # 将MultiDict数据处理为JSON数据

if __name__ == '__main__':
    app.run(debug=True)
