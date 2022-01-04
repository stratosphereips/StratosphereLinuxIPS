from flask import Flask, render_template, request
import redis
import json
# from slips_files.core.database import __database__

app = Flask(__name__)

# Connection to Slips redis database
config = ""
# __database__.start(config)
__database__ =redis.StrictRedis(host='localhost',
                                           port=6379,
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
@app.route('/timeline/profile_<ip>/<timewindow>')
def timeline(ip, timewindow):
    """
    Create a datatable with Slips alerts in flask web.
    Data is stored in a route "/timeline".
    """
    timeline = __database__.hgetall('profile_'+ip+"_"+timewindow+"_flows")
    flows = [json.loads(value) for key,value in timeline.items()]
    data_length = len(flows)
    total_filtered = len(flows)
    search = request.args.get('search[value]')

    # search
    if search:
        flows = [element for element in flows if element['proto'].lower() == search.lower()]
        total_filtered = len(flows)

    # pagination
    start = request.args.get('start', type=int)
    length = request.args.get('length', type=int)
    timeline_page = []
    if start and length:
        timeline_page = flows[start:(start + length)]

    return {
        'data': timeline_page if timeline_page else flows,
        'recordsFiltered': total_filtered,
        'recordsTotal': data_length,
        'draw': request.args.get('draw', type=int)
    }


if __name__ == '__main__':
    app.run()
