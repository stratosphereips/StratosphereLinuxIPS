from flask.signals import Namespace

namespace = Namespace()
message_sent = namespace.signal('update_db')