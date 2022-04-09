from flask import Flask, render_template, request
from hotkeys.hotkeys import hotkeys

app = Flask(__name__)


app = Flask(__name__)
app.register_blueprint(hotkeys)

if __name__ == '__main__':
    app.run()
