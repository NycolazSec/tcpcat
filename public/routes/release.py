from flask import Blueprint, render_template

release_bp = Blueprint('release', __name__, template_folder='templates')

@release_bp.route('/release')
def release():
    return render_template('releases.html', active='release')
