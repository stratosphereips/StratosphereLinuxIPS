from flask import Blueprint
from flask import Flask, render_template, request
import redis
import json


class General:

    def __init__(self, database, cache):
        self.db = database
        self.cache = cache
        self.bp = Blueprint('general', __name__, static_folder='static', static_url_path='/general/static',
                            template_folder='templates')

        # Routes should be set explicity, because Flask process self parameter in function wrong.
        self.bp.add_url_rule("/", view_func=self.index)
        self.bp.add_url_rule("/blockedProfileTWs", view_func=self.setBlockedProfileTWs)

    def index(self):
        return render_template('general.html')

    def setBlockedProfileTWs(self):
        '''
        Function to set blocked profiles and tws
        '''
        blockedProfileTWs = self.db.smembers('BlockedProfTW')
        data = []
        id = 0
        for blocked in blockedProfileTWs:
            data.append({"blocked": blocked})
            id = id + 1
        data_length = id
        total_filtered = id
        return {
            'data': data,
            'recordsFiltered': total_filtered,
            'recordsTotal': data_length,
            'draw': request.args.get('draw', type=int)
        }
