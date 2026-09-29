from flask import Blueprint, render_template

oem_bp = Blueprint('oem', __name__, template_folder='templates')


@oem_bp.route('/oem')
def oem():
    return render_template('oem.html', active='oem')
