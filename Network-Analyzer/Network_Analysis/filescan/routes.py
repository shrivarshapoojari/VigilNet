from flask import render_template, request, redirect, url_for, send_file, flash, current_app
from filescan import filescan_bp
from werkzeug.utils import secure_filename
import os
import hashlib
import sqlite3
import shutil
import time
import getpass
from winotify import Notification, audio  # type: ignore

# Icon path setup
import sys
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
logo_path = os.path.join(parent_dir, 'Logo', 'Logo.ico')
db_file = os.path.join(parent_dir, 'Malware Hash Database', 'hashes.db')
QUARANTINE_DIR = os.path.join(parent_dir, 'Quarantine')
# Create quarantine folder if not exists
os.makedirs(QUARANTINE_DIR, exist_ok=True)

def get_file_hashes(file_path):
    hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                for hash_obj in hashes.values():
                    hash_obj.update(chunk)
        return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
    except (FileNotFoundError, IOError) as e:
        print(f"🚫 Error reading file: {e}")
        return None

def check_hashes_in_db(hashes, file_path):
    try:
        if not os.path.exists(db_file):
            raise FileNotFoundError(f"🚫 Database file '{db_file}' not found.")

        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        found = False

        for hash_type, hash_value in hashes.items():
            cursor.execute(f"SELECT * FROM {hash_type} WHERE hash = ?", (hash_value,))
            result = cursor.fetchone()

            if result:
                found = True
                file_name = os.path.basename(file_path)
                new_path = os.path.join(QUARANTINE_DIR, file_name)
                shutil.move(file_path, new_path)

                toast = Notification(app_id="Secure Drive",
                                     title="🚨 Virus Detected!",
                                     msg="The file has been placed in quarantine.",
                                     icon=logo_path)
                toast.set_audio(audio.Default, loop=False)
                toast.show()

                conn.close()
                return 'infected', file_name

        toast = Notification(app_id="Secure Drive",
                             title="✅ No Virus Found",
                             msg="The file is clean!",
                             icon=logo_path)
        toast.set_audio(audio.Default, loop=False)
        toast.show()

        conn.close()
        return 'clean', None

    except Exception as e:
        print(f"⚠️ An unexpected error occurred: {e}")
        return 'error', None


@filescan_bp.route('/scan_file', methods=['GET', 'POST'])
def scan_file():
    result = None
    if request.method == 'POST':
        if 'file' not in request.files:
            result = "🚫 No file part"
        else:
            file = request.files['file']
            if file.filename == '':
                result = "🚫 No selected file"
            else:
                filename = secure_filename(file.filename)
                upload_folder = current_app.config.get('UPLOAD_FOLDER', 'temp_upload')
                os.makedirs(upload_folder, exist_ok=True)
                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)

                hashes = get_file_hashes(file_path)
                if hashes:
                    result = check_hashes_in_db(hashes, file_path)
                else:
                    result = "❌ Failed to compute hashes."
    return render_template('file_scan/scan_file.html', result=result)
@filescan_bp.route('/open_quarantine')
def open_quarantine():
    try:
        files = os.listdir(QUARANTINE_DIR)
        files = [f for f in files if os.path.isfile(os.path.join(QUARANTINE_DIR, f))]
    except Exception as e:
        files = []
    return render_template('file_scan/quarantine.html', files=files)

@filescan_bp.route('/download_quarantine/<path:filename>')
def download_quarantine(filename):
    try:
        return send_file(os.path.join(QUARANTINE_DIR, filename), as_attachment=True)
    except Exception as e:
        return f"⚠️ Error downloading file: {e}", 404