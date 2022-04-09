from flask import Blueprint
from flask import Flask, render_template, request
import redis
import json

hotkeys = Blueprint('hotkeys', __name__,  static_folder='static',static_url_path='/hotkeys/static', template_folder='templates')

# Connection to Slips redis database
config = ""

__database__ =redis.StrictRedis(host='localhost',
                                           port=6379,
                                           db=0,
                                           charset="utf-8",
                                           socket_keepalive=True,
                                           retry_on_timeout=True,
                                           decode_responses=True,
                                           health_check_interval=30)

# pubsub = __database__.pubsub()
# c1 = pubsub.subscribe('tw_modified')
# message = c1.get_message()
# if message:
#     print(message)

__cache__ = redis.StrictRedis(host='localhost',
                                                port=6379,
                                                db=1,
                                                charset="utf-8",
                                                socket_keepalive=True,
                                                retry_on_timeout=True,
                                                decode_responses=True,
                                                health_check_interval=30)

@hotkeys.route('/')
def index():
    return render_template('hotkeys.html', title='Slips')

@hotkeys.route('/info/<ip>')
def set_ip_info(ip):
    '''
    Set info about the ip in route /info/<ip> (geocountry, asn, TI)
    '''
    ip_info = json.loads(__cache__.hget('IPsInfo', ip))
    data = []
    # Hardcoded fields due to the complexity of data in side. Ex: {"asn":{"asnorg": "CESNET", "timestamp": 0.001}}
    geocountry = ip_info.get('geocountry', '-')
    asn = ip_info.get('asn', '-')
    asnorg = [asn.get('asnorg','-') if isinstance(asn, dict) else '-']
    reverse_dns = ip_info.get('reverse_dns', '-')
    data.append({'ip':ip,'geocountry': geocountry, 'asnorg': asnorg, 'reverse_dns': reverse_dns})

    return {
        'data': data,
        'recordsFiltered': len(data),
        'recordsTotal': len(data),
        'draw': request.args.get('draw', type=int)
    }

@hotkeys.route('/profiles_tws')
def profile_tws():
    '''
    Set profiles and their timewindows data into the tree.
    '''
    profiles = __database__.smembers('profiles')
    data = []
    id = 0
    for profileid in profiles:
        tws = __database__.zrange("tws" + profileid, 0, -1)
        data.append({"id": str(id), "profile": profileid.split("_")[1], "tws": tws})
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

@hotkeys.route('/outtuples/<ip>/<timewindow>')
def set_outtuples(ip, timewindow):
    """
    Create a datatable with Slips alerts.
    Data is stored in a route "/alerts/<ip>".
    """
    outtuples = __database__.hget(ip + '_'+ timewindow,'OutTuples')
    outtuples = json.loads(outtuples)
    data = []
    for key,value in outtuples.items():
        data.add({'tuple':key,'string':value[0]})
    data_length = len(outtuples)
    total_filtered = len(outtuples)
    search = request.args.get('search[value]')
    # search
    if search:
        data = [element for element in data if element['dport_name'].lower() == search.lower()]
        total_filtered = len(data)
    # pagination
    start = request.args.get('start', type=int)
    length = request.args.get('length', type=int)
    data_page = []
    if start and length:
        data_page = outtuples[start:(start + length)]

    return {
        'data': data_page if data_page else data,
        'recordsFiltered': total_filtered,
        'recordsTotal': data_length,
        'draw': request.args.get('draw', type=int)
    }

@hotkeys.route('/timeline_flows/profile_<ip>/<timewindow>')
def set_timeline_flows(ip, timewindow):
    """
    Set timeline flows of a chosen profile and timewindow. Supports pagination, sorting and seraching.
    """
    timeline = __database__.hgetall('profile_'+ip+"_"+timewindow+"_flows")
    data = [json.loads(value) for key,value in timeline.items()]
    data_length = len(data)
    total_filtered = len(data)

    # search
    search = request.args.get('search[value]')
    if search:
        data = [element for element in data if element['proto'].lower() == search.lower()]
        total_filtered = len(data)

    # pagination
    start = request.args.get('start', type=int)
    length = request.args.get('length', type=int)
    data_page = []
    if start and length:
        data_page = data[start:(start + length)]

    return {
        'data': data_page if data_page else data,
        'recordsFiltered': total_filtered,
        'recordsTotal': data_length,
        'draw': request.args.get('draw', type=int)
    }

@hotkeys.route('/timeline/profile_<ip>/<timewindow>')
def set_timeline(ip, timewindow):
    """
    Set timeline data of a chosen profile and timewindow. Supports pagination, sorting and seraching.
    """
    timeline = __database__.zrange('profile_'+ip+"_"+timewindow+"_timeline", 0, -1)
    data = [json.loads(line) for line in timeline]
    data_length = len(data)
    total_filtered = len(data)
    search = request.args.get('search[value]')

    # search
    if search:
        data = [element for element in data if element['proto'].lower() == search.lower()]
        total_filtered = len(data)

    # pagination
    start = request.args.get('start', type=int)
    length = request.args.get('length', type=int)
    data_page = []
    if start and length:
        data_page = data[start:(start + length)]

    return {
        'data': data_page if data_page else data,
        'recordsFiltered': total_filtered,
        'recordsTotal': data_length,
        'draw': request.args.get('draw', type=int)
    }

@hotkeys.route('/alerts/profile_<ip>/<timewindow>')
def set_alerts(ip, timewindow):
    """
    Set alerts data of a chosen profile and timewindow. Supports pagination, sorting and seraching.
    """
    timeline = __database__.zrange('profile_'+ip+"_"+timewindow+"_timeline", 0, -1)
    data = [json.loads(line) for line in timeline]
    data_length = len(data)
    total_filtered = len(data)
    search = request.args.get('search[value]')

    # search
    if search:
        data = [element for element in data if element['proto'].lower() == search.lower()]
        total_filtered = len(data)

    # pagination
    start = request.args.get('start', type=int)
    length = request.args.get('length', type=int)
    data_page = []
    if start and length:
        data_page = data[start:(start + length)]

    return {
        'data': data_page if data_page else data,
        'recordsFiltered': total_filtered,
        'recordsTotal': data_length,
        'draw': request.args.get('draw', type=int)
    }
