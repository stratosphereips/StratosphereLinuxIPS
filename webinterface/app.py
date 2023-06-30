from flask import Flask, render_template, redirect, url_for, current_app

from database.database import __database__
from database.signals import message_sent
from analysis.analysis import analysis
from general.general import general
from documentation.documentation import documentation
from utils import *



def create_app():
    app = Flask(__name__)
    app.config['JSON_SORT_KEYS'] = False  # disable sorting of timewindows
    return app


app = create_app()

@app.route('/redis')
def read_redis_port():
    res = read_db_file()
    return {"data" : res}

@app.route('/')
def index():
    return render_template('app.html', title='Slips')

@app.route('/db/<new_port>')
def get_post_javascript_data(new_port):

    message_sent.send(
        current_app._get_current_object(),
        port=int(new_port),
        dbnumber=0
    )
    return redirect(url_for('index'))

@app.route('/info')
def set_pcap_info():
    """
    Set information about the pcap.
    """
    info = __database__.db.hgetall("analysis")

    profiles = __database__.db.smembers('profiles')
    info["num_profiles"] = len(profiles) if profiles else 0

    alerts = __database__.db.hgetall('alerts')
    info["num_alerts"] = len(alerts) if alerts else 0



    return info


if __name__ == '__main__':
    # parser = ArgumentParser()
    # parser.add_argument('-p')
    # args = parser.parse_args()
    # port = args.p

    app.register_blueprint(analysis, url_prefix="/analysis")

    app.register_blueprint(general, url_prefix="/general")
    
    app.register_blueprint(documentation, url_prefix="/documentation")

    app.run(host="0.0.0.0", port=55000)

