from flask import Blueprint

filescan_bp = Blueprint('filescan', __name__, template_folder='../templates/file_scan')

from filescan import routes
