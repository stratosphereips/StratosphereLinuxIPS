from flask import Flask, render_template, request
import redis
import json
# from slips_files.core.database import __database__

app = Flask(__name__)

# Connection to Slips redis database
config = ""
# __database__.start(config)
__database__ = redis.StrictRedis("localhost",6379,charset="utf-8", decode_responses=True)


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

@app.route('/info/<ip>')
def ip_info(ip):
    ip_info = __cache__.hget('IPsInfo', ip)
    print(ip_info)
    return ip_info

@app.route('/profiles_tws')
def profile_tws():
    profile_tws = __database__.hgetall('Profiles_TWs')
    data = []
    id = 0
    for profileid, tws in profile_tws.items():
        data.append({"id": str(id), "profile": profileid, "tws": json.loads(tws)})
        id = id + 1
    # start = request.args.get('start', type=int)
    # length = request.args.get('length', type=int)
    data_length = id
    total_filtered = id
    # profiles_page = data[start:(start + length)]

    return {
        'data': data,
        'recordsFiltered': total_filtered,
        'recordsTotal': data_length,
        'draw': request.args.get('draw', type=int)
    }


@app.route('/alerts')
def alerts():
    """
    Create a datatable with Slips alerts in flask web.
    Data is stored in a route "/alerts".

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
    alerts_page = ""
    # alerts_page = []
    # if start and length:
    alerts_page = alerts[start:(start + length)]

    return {
        'data': alerts_page,
        'recordsFiltered': total_filtered,
        'recordsTotal': data_length,
        'draw': request.args.get('draw', type=int)
    }


if __name__ == '__main__':
    app.run()
