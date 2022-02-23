from flask import Flask, render_template, request
import redis
import json
# from slips_files.core.database import __database__

app = Flask(__name__)

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

__cache__ = redis.StrictRedis(host='localhost',
                                                port=6379,
                                                db=1,
                                                charset="utf-8",
                                                socket_keepalive=True,
                                                retry_on_timeout=True,
                                                decode_responses=True,
                                                health_check_interval=30)

@app.route('/')
def index():
    return render_template('interface.html', title='Slips')

@app.route('/info/<ip>')
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

@app.route('/profiles_tws')
def profile_tws():
    '''
    Set profiles and their timewindows data.
    '''
    profile_tws = __database__.hgetall('Profiles_TWs')
    data = []
    id = 0
    for profileid, tws in profile_tws.items():
        data.append({"id": str(id), "profile": profileid.split("_")[1], "tws": json.loads(tws)})
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

@app.route('/outtuples/<ip>/<timewindow>')
def set_outtuples(ip, timewindow):
    """
    Create a datatable with Slips alerts.
    Data is stored in a route "/alerts/<ip>".
    """
    outtuples = __database__.hget(ip + '_'+ timewindow,'OutTuples')
    outtuples = json.loads(outtuples)
    data = []
    for key,value in outtuples.items():
        data.append({'tuple':key,'string':value[0]})
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

@app.route('/timeline_flows/profile_<ip>/<timewindow>')
def set_timeline_flows(ip, timewindow):
    """
    Set timeline flows of a chosen profile and timewindow. Supports pagination, sorting and seraching.
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

@app.route('/timeline/profile_<ip>/<timewindow>')
def set_timeline(ip, timewindow):
    """
    Set timeline data of a chosen profile and timewindow. Supports pagination, sorting and seraching.
    """
    timeline = __database__.zrange('profile_'+ip+"_"+timewindow+"_timeline", 0, -1)
    print(timeline)
    flows = [json.loads(line) for line in timeline]
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
