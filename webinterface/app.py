from flask import Flask, render_template, request
from hotkeys.hotkeys import hotkeys
from general.general import general

app = Flask(__name__)
app.register_blueprint(hotkeys)
app.register_blueprint(general, url_prefix="/general")

if __name__ == '__main__':
    app.run(debug=True)