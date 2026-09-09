from flask import Flask, render_template


import routes.release as release
import routes.notice as notice

app = Flask(__name__, template_folder='templates')

app.register_blueprint(release.release_bp)
app.register_blueprint(notice.notice_bp)

@app.route('/')
def undex():
    return render_template('index.html')

if __name__ == '__main__':
    app.run()