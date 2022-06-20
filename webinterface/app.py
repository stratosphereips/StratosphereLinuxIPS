from flask import Flask, render_template, request
from hotkeys.hotkeys import hotkeys
from general.general import general

app = Flask(__name__)
app.register_blueprint(hotkeys, url_prefix="/hotkeys")
app.register_blueprint(general, url_prefix="/general")

@app.route('/')
def index():
    return render_template('base.html', title='Slips')

if __name__ == '__main__':
    app.run(debug=True)