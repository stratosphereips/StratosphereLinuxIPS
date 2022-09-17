from database.database import __database__

from analysis.analysis import analysis
from general.general import general
from argparse import ArgumentParser


def create_app():
    app = Flask(__name__)
    app.config['JSON_SORT_KEYS'] = False  # disable sorting of timewindows
    return app


app = create_app()


@app.route('/')
def index():
    return render_template('app.html', title='Slips')

@app.route('/info')
def set_pcap_info():
    """
    Set information about the pcap.
    """
    info = __database__.db.hgetall("analysis")
    return info


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-p')
    args = parser.parse_args()
    port = args.p

    app.register_blueprint(analysis, url_prefix="/analysis")

    app.register_blueprint(general, url_prefix="/general")

    app.run(host="0.0.0.0", port=55000)
