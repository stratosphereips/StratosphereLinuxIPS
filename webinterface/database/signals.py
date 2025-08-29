# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from flask.signals import Namespace

namespace = Namespace()
message_sent = namespace.signal("update_db")
