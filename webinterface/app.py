from flask import Flask, render_template, request
from hotkeys.hotkeys import hotkeys
from general.general import general
import json
import redis

app = Flask(__name__)
app.register_blueprint(hotkeys, url_prefix="/hotkeys")
app.register_blueprint(general, url_prefix="/general")

__database__ = redis.StrictRedis(host='localhost',
                                 port=32774,
                                 db=0,
                                 charset="utf-8",
                                 socket_keepalive=True,
                                 retry_on_timeout=True,
                                 decode_responses=True,
                                 health_check_interval=30)


@app.route('/')
def index():
    return render_template('base.html', title='Slips')

@app.route('/info')
def set_pcap_info():
    """
    Set information about the pcap.
    """
    info = __database__.hgetall("analysis")
    return info

if __name__ == '__main__':
    app.run(debug=True)