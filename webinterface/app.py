from flask import Flask, render_template, request
from hotkeys.hotkeys import Hotkeys
from general.general import general
from argparse import ArgumentParser
import redis

app = Flask(__name__)

__database__ = redis.StrictRedis(host='localhost',
                                 port=32785,
                                 db=0,
                                 charset="utf-8",
                                 socket_keepalive=True,
                                 retry_on_timeout=True,
                                 decode_responses=True,
                                 health_check_interval=30)

__cache__ = redis.StrictRedis(host='localhost',
                                 port=6379,
                                 db=1,
                                 charset="utf-8",
                                 socket_keepalive=True,
                                 retry_on_timeout=True,
                                 decode_responses=True,
                                 health_check_interval=30)

hotkey = Hotkeys(__database__, __cache__)
app.register_blueprint(hotkey.bp, url_prefix="/hotkeys")
app.register_blueprint(general, url_prefix="/general")

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
    parser = ArgumentParser()
    parser.add_argument('-p')
    args = parser.parse_args()
    port = args.p

    app.run()