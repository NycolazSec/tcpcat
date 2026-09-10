from flask import Blueprint, render_template

internals_bp = Blueprint('internals', __name__, template_folder='templates')

@internals_bp.route('/internals')
def internals():
    return render_template('internals.html', active='internals')
