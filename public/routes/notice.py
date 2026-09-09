from flask import Blueprint, render_template

notice_bp = Blueprint('notice', __name__, template_folder='templates')

@notice_bp.route('/notice')
def notice():
    return render_template('notice.html')