from flask import Flask, render_template, request, redirect, url_for, send_file,session
from Utils.capture import start_capture
from Utils.analysis import analyze_packet
from Utils.filters import parse_filter_string
from Utils.save import save_to_txt, save_to_pcap
from Utils.hostDetector import detect_live_hosts
from datetime import datetime
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'captures'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.secret_key = 'your-very-secret-key-12345'
captured_packets = []

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/capture', methods=['POST', 'GET'])
def capture():
    global captured_packets 
    packets_info = []
    
    if request.method == 'POST':
        interface = request.form.get('interface')
        packet_count = int(request.form.get('packet_count', 10))
        filter_str = request.form.get('filter', 'ALL')

        filter_criteria = parse_filter_string(filter_str)
        captured_packets = start_capture(interface, packet_count, filter_criteria)
        
        if isinstance(captured_packets, dict) and 'error' in captured_packets:
            return render_template('capture.html', error=captured_packets['error'])
        
        for pkt in captured_packets:
            packets_info.append(analyze_packet(pkt))

        # Save files immediately after capture
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        txt_filename = f"txt_capture_{timestamp}.txt"
        pcap_filename = f"pcap_capture_{timestamp}.pcap"
        txt_path = os.path.join(app.config['UPLOAD_FOLDER'], txt_filename)
        pcap_path = os.path.join(app.config['UPLOAD_FOLDER'], pcap_filename)

        save_to_txt(captured_packets, txt_path)
        save_to_pcap(captured_packets, pcap_path)

        # Store filenames in session for download
        session['txt_file'] = txt_filename
        session['pcap_file'] = pcap_filename

        return render_template('capture.html', packets=packets_info)
    
    return render_template('capture.html')
@app.route('/save/<filetype>')
def save(filetype):
    if filetype == 'txt':
        filename = session.get('txt_file')
    elif filetype == 'pcap':
        filename = session.get('pcap_file')
    else:
        return "Invalid file type"

    if not filename:
        return "No capture file available to download."

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
        return "File not found."

    return send_file(filepath, as_attachment=True)

@app.route('/live-hosts', methods=['GET', 'POST'])
def live_hosts():
    hosts = []
    if request.method == 'POST':
        local_ip = request.form.get('local_ip')
        if local_ip:
            result = detect_live_hosts(local_ip)
              # For debugging
            # Extract 'hosts' list if present, else empty list
            hosts = result.get('hosts', []) if isinstance(result, dict) else []
    return render_template('live_hosts.html', hosts=hosts)



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)