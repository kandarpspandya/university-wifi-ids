import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
from network_monitor import start_background_monitoring, get_packet_counts, get_traffic_data
from intrusion_detection import analyze_traffic, deep_scan, scan_file
import time

app = Flask(__name__)
socketio = SocketIO(app)

VIRUSTOTAL_API_KEY = "d90783f2fc5800160ffcd218055749bf731a22da3c0f6109a07e1cda6f88fc3b"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan_file", methods=["POST"])
def scan_file_route():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded"})

    result = scan_file(file.read(), file.filename, VIRUSTOTAL_API_KEY)
    return jsonify(result)

@app.route("/deep_scan", methods=["POST"])
def deep_scan_route():
    target = request.form.get("target")
    if not target:
        return jsonify({"error": "No target IP provided"})

    result = deep_scan(target)
    return jsonify(result)

def send_graph_data():
    while True:
        graph_data = get_packet_counts()
        traffic = get_traffic_data()
        for item in traffic:
            if 'src_ip' in item:
                analyze_traffic(item['src_ip'])
            elif 'domain' in item:
                analyze_traffic(item['domain'])

        with app.app_context():
            socketio.emit("graph_data", {"data": graph_data, "traffic": traffic})
        time.sleep(1)

if __name__ == "__main__":
    start_background_monitoring()
    socketio.start_background_task(send_graph_data)
    socketio.run(app, host='0.0.0.0', debug=True)