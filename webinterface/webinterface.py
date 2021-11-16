from flask import Flask, render_template, request
import redis
import json
# from slips_files.core.database import __database__
app = Flask(__name__)

# Connection to Slips redis database
config = ""
# __database__.start(config)
__database__ = redis.Redis("localhost")
# alerts_channel = __database__.subscribe('evidence_added')

#
# def run():
#     """
#     Waits for the database updates from channels.
#     """
#     while True:
#         message = alerts_channel.get_message(timeout=None)
#         if message['channel'] == 'evidence_added' and type(message['data']) is not int:
#             data = json.loads(message['data'])
#             alerts(data)


@app.route('/')
def index():
    return render_template('interface.html', title='Slips')


@app.route('/alerts/')
def alerts():
    """
    Create a databse of alerts in flask
    """
    alerts = __database__.smembers('Evidence')
    alerts = [json.loads(element) for element in alerts]
    data_length = len(alerts)
    total_filtered = len(alerts)
    search = request.args.get('search[value]')
    if search:
        alerts = [element for element in alerts if element['dport_name'].lower() == search.lower()]
        total_filtered = len(alerts)
    # pagination
    start = request.args.get('start', type=int)
    length = request.args.get('length', type=int)
    alerts_page = alerts[start:(start+length)]

    return {
        'data': alerts_page,
        'recordsFiltered': total_filtered,
        'recordsTotal': data_length,
        'draw': request.args.get('draw', type=int)
    }



if __name__ == '__main__':
    app.run()
