from flask import Blueprint
from flask import Flask, render_template, request
import json
from collections import defaultdict


class Hotkeys:

    def __init__(self, database, cache):
        self.db = database
        self.cache = cache
        self.bp = Blueprint('hotkeys', __name__, static_folder='static', static_url_path='/hotkeys/static',
                            template_folder='templates')

        # Routes should be set explicity, because Flask process self parameter in function wrong.
        self.bp.add_url_rule("/", view_func=self.index)
        self.bp.add_url_rule("/profiles_tws", view_func=self.set_profile_tws)
        self.bp.add_url_rule("/info/<ip>", view_func=self.set_ip_info)
        self.bp.add_url_rule("/dstIP/<profile>/<timewindow>", view_func=self.set_DstIPflow)
        self.bp.add_url_rule("/outtuples/<profile>/<timewindow>", view_func=self.set_outtuples)
        self.bp.add_url_rule("/intuples/<profile>/<timewindow>", view_func=self.set_intuples)
        self.bp.add_url_rule("/DstPortsClientUDPNotEstablished", view_func=self.set_dstPortsClientUDPNotEstablished)
        self.bp.add_url_rule("/timeline_flows/<profile>/<timewindow>", view_func=self.set_timeline_flows)
        self.bp.add_url_rule("/timeline/<profile>/<timewindow>", view_func=self.set_timeline)

    def index(self):
        return render_template('hotkeys.html', title='Slips')

    def get_ip_info(self, ip):
        """
        Retrieve IP information from database
        :param ip: active IP
        :return: all data about the IP in database
        """
        ip_info = json.loads(self.cache.hget('IPsInfo', ip))

        # Hardcoded decapsulation due to the complexity of data in side. Ex: {"asn":{"asnorg": "CESNET", "timestamp": 0.001}}
        geocountry = ip_info.get('geocountry', '-')
        asn = ip_info.get('asn', '-')
        asnorg = [asn.get('asnorg', '-') if isinstance(asn, dict) else '-']
        reverse_dns = ip_info.get('reverse_dns', '-')

        data = {'geocountry': geocountry, 'asnorg': asnorg, 'reverse_dns': reverse_dns}
        return data

    def set_ip_info(self, ip):
        '''
        Set info about the ip in route /info/<ip> (geocountry, asn, TI)
        :param ip: active IP
        :return: information about IP in database
        '''
        ip_info = self.get_ip_info(ip)
        ip_info["ip"] = ip
        data = [ip_info]

        return {
            'data': data
        }

    def set_profile_tws(self):
        '''
        Set profiles and their timewindows into the tree. Blocked are highligted in red.
        :return: (profile, [tw, blocked], blocked)
        '''

        # Fetch blocked
        blockedProfileTWs = self.db.smembers('BlockedProfTW')
        dict_blockedProfileTWs = defaultdict(list)

        for blocked in blockedProfileTWs:
            profile_word, blocked_ip, blocked_tw = blocked.split("_")
            dict_blockedProfileTWs[blocked_ip].append(blocked_tw)

        # Fetch profiles
        profiles = self.db.smembers('profiles')
        data = []
        id = 0
        for profileid in profiles:
            profile_word, profile_ip = profileid.split("_")
            tws = self.db.zrange("tws" + profileid, 0, -1)
            dict_tws = {}
            blocked_profile = False

            for tw in tws:
                dict_tws[tw] = False

            if profile_ip in dict_blockedProfileTWs.keys():
                for blocked_tw in dict_blockedProfileTWs[profile_ip]:
                    dict_tws[blocked_tw] = True
                blocked_profile = True
            data.append({"id": str(id), "profile": profile_ip, "tws": dict_tws, "blocked": blocked_profile})
            id = id + 1

        return {
            'data': data
        }

    def set_DstIPflow(self, profile, timewindow):
        """
        Set flows per each destination IP
        :param profile: active profile
        :param timewindow: active timewindow
        :return: data with flows per ip
        """
        dst_ips = json.loads(self.db.hget(profile + '_' + timewindow, 'DstIPs'))
        data = []
        id = 0
        for ip, port in dst_ips.items():
            data.append({"ip": ip, "flow": port})
            id = id + 1

        return {
            'data': data
        }

    def set_dstPortsClientUDPNotEstablished(self):

        dst_ips = json.loads(self.db.hget('profile_192.168.2.16_timewindow1', 'DstPortsClientUDPNotEstablished'))
        data = []
        id = 0
        for port, info in dst_ips.items():
            data.append({"port": port, "info": info})
            id = id + 1

        return {
            'data': data
        }

    def set_outtuples(self, profile, timewindow):
        """
        Set outtuples of a chosen profile and timewindow.
        :param profile: active profile
        :param timewindow: active timewindow
        :return: (tuple, key, ip_info)
        """

        data = []
        outtuples = self.db.hget(profile + '_' + timewindow, 'OutTuples')
        if outtuples:
            outtuples = json.loads(outtuples)

            for key, value in outtuples.items():
                ip, port, protocol = key.split("-")
                ip_info = self.get_ip_info(ip)
                outtuple_dict = dict()
                outtuple_dict.update({'tuple': key, 'string': value[0]})
                outtuple_dict.update(ip_info)
                data.append(outtuple_dict)

        return {
            'data': data
        }

    def set_intuples(self, profile, timewindow):
        """
        Set intuples of a chosen profile and timewindow.
        :param profile: active profile
        :param timewindow: active timewindow
        :return: (tuple, string, ip_info)
        """
        data = []
        intuples = self.db.hget(profile + '_' + timewindow, 'InTuples')
        if intuples:
            intuples = json.loads(intuples)
            for key, value in intuples.items():
                ip, port, protocol = key.split("-")
                ip_info = self.get_ip_info(ip)

                outtuple_dict = dict()
                outtuple_dict.update({'tuple': key, 'string': value[0]})
                outtuple_dict.update(ip_info)
                data.append(outtuple_dict)

        return {
            'data': data
        }

    def set_timeline_flows(self, profile, timewindow):
        """
        Set timeline flows of a chosen profile and timewindow.
        :param profile: active profile
        :param timewindow: active timewindow
        :return: list of timeline flows as set initially in database
        """
        data = []
        timeline_flows = self.db.hgetall(profile + "_" + timewindow + "_flows")
        if timeline_flows:
            data = [json.loads(value) for key, value in timeline_flows.items()]

        return {
            'data': data
        }

    def set_timeline(self, profile, timewindow):
        """
        Set timeline data of a chosen profile and timewindow
        :param profile: active profile
        :param timewindow: active timewindow
        :return: list of timeline as set initially in database
        """
        data = []
        timeline = self.db.zrange(profile + "_" + timewindow + "_timeline", 0, -1)
        if timeline:
            data = [json.loads(line) for line in timeline]

        return {
            'data': data
        }
