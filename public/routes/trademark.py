from flask import Blueprint, render_template

trademark_bp = Blueprint('trademark', __name__, template_folder='templates')


@trademark_bp.route('/trademark')
def trademark():
    return render_template('trademark.html', active='trademark')
