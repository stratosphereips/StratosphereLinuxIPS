from flask import Blueprint
from flask import render_template
from database.database import __database__

general = Blueprint('general', __name__, static_folder='static', static_url_path='/general/static',
                            template_folder='templates')


@general.route("/")
def index():
    return render_template('general.html')


@general.route("/blockedProfileTWs")
def setBlockedProfileTWs():
    '''
    Function to set blocked profiles and tws
    '''
    blockedProfileTWs = __database__.db.hgetall('BlockedProfTW')
    data = []

    if blockedProfileTWs:
        for profile, tws in blockedProfileTWs.items():
            data.append({"blocked": profile + str(tws)})

    return {
        'data': data,
    }




