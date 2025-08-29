#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2015 Cesnet z.s.p.o
# Use of this source is governed by a 3-clause BSD-style license, see LICENSE file.

import json
import logging
import logging.handlers
import time
import http.client
from urllib.parse import urlparse
from urllib.parse import urlencode
from sys import stderr, exc_info
from traceback import format_tb
from os import path
from operator import itemgetter
from pathlib import Path

VERSION = "3.0-beta2"


class Error(Exception):
    """Object for returning error messages to calling application.
    Caller can test whether it received data or error by checking
    isinstance(res, Error).
    However if he does not want to deal with errors altogether,
    this error object also returns False value if used in Bool
    context (e.g. in "if res: print res" print is not evaluated),
    and also acts as empty iterator (e.g. in "for e in res: print e"
    print is also not evaluated).
    Also, it can be raised as an exception.
    """

    def __init__(self, method=None, req_id=None, errors=None, **kwargs):
        self.errors = []
        if errors:
            self.extend(method, req_id, errors)
        if kwargs:
            self.append(method, req_id, **kwargs)

    def append(self, method=None, req_id=None, **kwargs):
        # We shift method and req_id into each and every error, because
        # we want to be able to simply merge more Error arrays (for
        # returning errors from more Warden calls at once
        if method and "method" not in kwargs:
            kwargs["method"] = method
        if req_id and "req_id" not in kwargs:
            kwargs["req_id"] = req_id
        # Ugly, but be paranoid, don't rely on server reply to be well formed
        try:
            kwargs["error"] = int(kwargs["error"])
        except Exception:
            kwargs["error"] = 0
        if "events" in kwargs:
            evlist = kwargs["events"]
            try:
                evlist_new = []
                for ev in evlist:
                    try:
                        evlist_new.append(int(ev))
                    except Exception:
                        pass
                kwargs["events"] = evlist_new
            except Exception:
                kwargs["events"] = []
        if "events_id" in kwargs:
            try:
                iter(kwargs["events_id"])
            except TypeError:
                kwargs["events_id"] = [None] * len(kwargs["events"])
        if "send_events_limit" in kwargs:
            try:
                kwargs["send_events_limit"] = int(kwargs["send_events_limit"])
            except Exception:
                del kwargs["send_events_limit"]
        self.errors.append(kwargs)

    def extend(self, method=None, req_id=None, iterable=None):
        if iterable is None:
            iterable = []
        try:
            iter(iterable)
        except TypeError:
            iterable = []  # Bad joke from server
        for e in iterable:
            try:
                args = dict(e)
            except TypeError:
                args = {}  # Not funny!
            self.append(method, req_id, **args)

    def __len__(self):
        """In list or iterable context we're empty"""
        return 0

    def __iter__(self):
        """We are the iterator"""
        return self

    def next(self):
        """In list or iterable context we're empty"""
        raise StopIteration

    def __bool__(self):
        """In boolean context we're never True"""
        return False

    def __str__(self):
        out = []
        for e in self.errors:
            out.extend((self.str_err(e), self.str_info(e)))
        return "\n".join(out)

    def log(self, logger=None, prio=logging.ERROR):
        if not logger:
            logger = logging.getLogger()
        for e in self.errors:
            logger.log(prio, self.str_err(e))
            if info := self.str_info(e):
                logger.info(info)
            if debug := self.str_debug(e):
                logger.debug(debug)

    def str_preamble(self, e):
        return "%08x/%s" % (e.get("req_id", 0), e.get("method", "?"))

    def str_err(self, e):
        out = [self.str_preamble(e)]
        out.append(
            f" Error({e.get('error', 0)}) {e.get('message', 'Unknown error')} "
        )
        if "exc" in e and e["exc"]:
            out.append(
                f"(cause was {e['exc'][0].__name__}: {str(e['exc'][1])})"
            )
        return "".join(out)

    def str_info(self, e):
        ecopy = dict(e)  # shallow copy
        ecopy.pop("req_id", None)
        ecopy.pop("method", None)
        ecopy.pop("error", None)
        ecopy.pop("message", None)
        ecopy.pop("exc", None)
        return (
            "%s Detail: %s"
            % (
                self.str_preamble(e),
                json.dumps(ecopy, default=lambda v: str(v)),
            )
            if ecopy
            else ""
        )

    def str_debug(self, e):
        out = [self.str_preamble(e)]
        if "exc" not in e or not e["exc"]:
            return ""
        if exc_tb := e["exc"][2]:
            out.append("Traceback:\n")
            out.extend(format_tb(exc_tb))
        return "".join(out)


class Client(object):
    def __init__(
        self,
        url,
        certfile=None,
        keyfile=None,
        cafile=None,
        timeout=60,
        retry=3,
        pause=5,
        get_events_limit=6000,
        send_events_limit=500,
        errlog=None,
        syslog=None,
        filelog=None,
        idstore=None,
        name="org.example.warden.test",
        secret=None,
    ):
        if errlog is None:
            errlog = {}
        self.name = name
        self.secret = secret
        # Init logging as soon as possible and make sure we don't
        # spit out exceptions but just log or return Error objects
        self.init_log(errlog, syslog, filelog)

        self.url = urlparse(url, allow_fragments=False)

        self.conn = None

        base = path.join(path.dirname(__file__))
        self.certfile = path.join(base, certfile or "cert.pem")
        self.keyfile = path.join(base, keyfile or "key.pem")
        self.cafile = path.join(base, cafile or "ca.pem")
        self.timeout = int(timeout)
        self.get_events_limit = int(get_events_limit)
        self.idstore = (
            path.join(base, idstore) if idstore is not None else None
        )

        self.send_events_limit = int(send_events_limit)
        self.retry = int(retry)
        self.pause = int(pause)

        self.ciphers = "TLS_RSA_WITH_AES_256_CBC_SHA"
        self.getInfo()  # Call to align limits with server opinion

    def create_file(self, filepath):
        """
        create the file and dir if they don't exist
        """
        if path.exists(filepath):
            return
        dir = path.dirname(filepath)
        # filename = path.basename(filepath)
        p = Path(dir)
        p.mkdir(parents=True, exist_ok=True)
        open(filepath, "w").close()

    def init_log(self, errlog: dict, syslog: dict, filelog: dict):
        def loglevel(lev):
            try:
                return int(getattr(logging, lev.upper()))
            except (AttributeError, ValueError):
                self.logger.warning(f'Unknown loglevel "{lev}", using "debug"')
                return logging.DEBUG

        def facility(fac):
            try:
                return int(
                    getattr(
                        logging.handlers.SysLogHandler, f"LOG_{fac.upper()}"
                    )
                )
            except (AttributeError, ValueError):
                self.logger.warning(
                    f'Unknown syslog facility "{fac}", using "local7"'
                )
                return logging.handlers.SysLogHandler.LOG_LOCAL7

        form = (
            "%(filename)s[%(process)d]: %(name)s (%(levelname)s) %(message)s"
        )
        format_notime = logging.Formatter(form)
        format_time = logging.Formatter(f"%(asctime)s {form}")

        self.logger = logging.getLogger(self.name)
        self.logger.propagate = False  # Don't bubble up to root logger
        self.logger.setLevel(logging.DEBUG)

        if errlog is not None:
            # create the file and dir if they don't exist
            self.create_file(errlog["file"])
            el = logging.StreamHandler(stderr)
            el.setFormatter(format_time)
            el.setLevel(loglevel(errlog.get("level", "info")))
            self.logger.addHandler(el)

        if filelog is not None:
            try:
                self.create_file(filelog["file"])
                fl = logging.FileHandler(
                    filename=filelog["file"],
                    encoding="utf-8",
                )
                fl.setLevel(loglevel(filelog.get("level", "debug")))
                fl.setFormatter(format_time)
                self.logger.addHandler(fl)
            except Exception:
                Error(
                    message="Unable to setup file logging", exc=exc_info()
                ).log(self.logger)

        if syslog is not None:
            self.create_file(syslog["file"])
            try:
                sl = logging.handlers.SysLogHandler(
                    address=syslog.get("socket", "/dev/log"),
                    facility=facility(syslog.get("facility", "local7")),
                )
                sl.setLevel(loglevel(syslog.get("level", "debug")))
                sl.setFormatter(format_notime)
                self.logger.addHandler(sl)
            except Exception:
                Error(
                    message="Unable to setup syslog logging", exc=exc_info()
                ).log(self.logger)

        if not (errlog or filelog or syslog):
            # User wants explicitly no logging, so let him shoot his socks off.
            # This silences complaining of logging module about no suitable
            # handler.
            self.logger.addHandler(logging.NullHandler())

    def log_err(self, err, prio=logging.ERROR):
        if isinstance(err, Error):
            err.log(self.logger, prio)
        return err

    def connect(self):
        try:
            if self.url.scheme == "https":
                conn = http.client.HTTPSConnection(
                    self.url.netloc,
                    key_file=self.keyfile,
                    cert_file=self.certfile,
                    timeout=self.timeout,
                )
            elif self.url.scheme == "http":
                conn = http.client.HTTPConnection(
                    self.url.netloc, timeout=self.timeout
                )
            else:
                return Error(
                    message='Don\'t know how to connect to "%s"'
                    % self.url.scheme,
                    url=self.url.geturl(),
                )
        except Exception:
            return Error(
                message="HTTP(S) connection failed",
                exc=exc_info(),
                url=self.url.geturl(),
                timeout=self.timeout,
                key_file=self.keyfile,
                cert_file=self.certfile,
                cafile=self.cafile,
                ciphers=self.ciphers,
            )

        return conn

    def sendRequest(self, func="", payload=None, **kwargs):
        if self.secret is None:
            kwargs["client"] = self.name
        else:
            kwargs["secret"] = self.secret

        if kwargs:
            for k in list(kwargs.keys()):
                if kwargs[k] is None:
                    del kwargs[k]
            argurl = f"?{urlencode(kwargs, doseq=True)}"
        else:
            argurl = ""

        try:
            data = "" if payload is None else json.dumps(payload)
        except Exception:
            return Error(
                message="Serialization to JSON failed",
                exc=exc_info(),
                method=func,
                payload=payload,
            )

        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Content-Length": str(len(data)),
        }

        # HTTP(S)Connection is oneshot object (and we don't speak "pipelining")
        conn = self.connect()
        if not conn:
            return conn  # either False of Error instance

        loc = f"{self.url.path}/{func}{argurl}"
        try:
            conn.request("POST", loc, data, self.headers)
        except Exception:
            conn.close()
            return Error(
                message="Sending of request to server failed",
                exc=exc_info(),
                method=func,
                log=loc,
                headers=self.headers,
                data=data,
            )

        try:
            res = conn.getresponse()
        except Exception:
            conn.close()
            return Error(
                method=func,
                message="HTTP reply failed",
                exc=exc_info(),
                loc=loc,
                headers=self.headers,
                data=data,
            )

        try:
            response_data = res.read()
        except Exception:
            conn.close()
            return Error(
                method=func,
                message="Fetching HTTP data from server failed",
                exc=exc_info(),
                loc=loc,
                headers=self.headers,
                data=data,
            )

        conn.close()

        if res.status == http.client.OK:
            try:
                data = json.loads(response_data)
            except Exception:
                data = Error(
                    method=func,
                    message="JSON message parsing failed",
                    exc=exc_info(),
                    response=response_data,
                )
        else:
            try:
                data = json.loads(response_data)
                data["errors"]  # trigger exception if not dict or no error key
            except Exception:
                data = Error(
                    method=func,
                    message="Generic server HTTP error",
                    error=res.status,
                    exc=exc_info(),
                    response=response_data,
                )
            else:
                data = Error(
                    method=data.get("method", None),
                    req_id=data.get("req_id", None),
                    errors=data.get("errors", []),
                )

        return data

    def _saveID(self, id, idstore=None):
        idf = idstore or self.idstore
        if not idf:
            return False
        try:
            with open(idf, "w+") as f:
                f.write(str(id))
        except (ValueError, IOError):
            # Use Error instance just for proper logging
            Error(
                message=f'Writing id file "{idf}" failed',
                exc=exc_info(),
                idstore=idf,
            ).log(self.logger, logging.INFO)
        return id

    def _loadID(self, idstore=None):
        idf = idstore or self.idstore
        if not idf:
            return None
        try:
            with open(idf, "r") as f:
                id = int(f.read())
        except (ValueError, IOError):
            Error(
                message=f'Reading id file "{idf}" failed, relying on server',
                exc=exc_info(),
                idstore=idf,
            ).log(self.logger, logging.INFO)
            id = None
        return id

    def getInfo(self):
        res = self.sendRequest("getInfo")
        if isinstance(res, Error):
            res.log(self.logger)
        else:
            try:
                self.send_events_limit = min(
                    res["send_events_limit"], self.send_events_limit
                )
                self.get_events_limit = min(
                    res["get_events_limit"], self.get_events_limit
                )
            except (AttributeError, TypeError, KeyError):
                pass
        return res

    def send_events_raw(self, events=None):
        if events is None:
            events = []
        return self.sendRequest("sendEvents", payload=events)

    def send_events_chunked(self, events=None):
        """Split potentially long "events" list to send_events_limit
        long chunks to avoid slap from server.
        """
        if events is None:
            events = []
        count = len(events)
        err = Error()
        send_events_limit = (
            self.send_events_limit
        )  # object stored value can change during sending
        for offset in range(0, count, send_events_limit):
            res = self.send_events_raw(
                events[offset : min(offset + send_events_limit, count)]
            )

            if isinstance(res, Error):
                # Shift all error indices by offset to correspond with 'events' list
                for e in res.errors:
                    evlist = e.get("events", [])
                    if srv_limit := e.get("send_events_limit"):
                        self.send_events_limit = min(
                            self.send_events_limit, srv_limit
                        )
                    for i in range(len(evlist)):
                        evlist[i] += offset
                err.errors.extend(res.errors)

        return err if err.errors else {}

    def sendEvents(self, events=None, q=None, retry=None, pause=None):
        """
        Send out "events" list to server, retrying on server errors.
        :param q: in case this function was called as a thread, this queue will hold the return value of it
        """

        if events is None:
            events = []
        ev = events
        idx_xlat = range(len(ev))
        err = Error()
        retry = retry or self.retry
        attempt = retry
        while ev and attempt:
            if attempt < retry:
                self.logger.info(
                    "%d transient errors, retrying (%d to go)"
                    % (len(ev), attempt)
                )
                time.sleep(pause or self.pause)
            res = self.send_events_chunked(ev)
            attempt -= 1

            next_ev = []
            next_idx_xlat = []
            if isinstance(res, Error):
                # Sort to process fatal errors first
                res.errors.sort(key=itemgetter("error"))
                for e in res.errors:
                    errno = e["error"]
                    evlist = e.get("events", range(len(ev)))  # none means all
                    if errno < 500 or not attempt:
                        # Fatal error or last try, translate indices
                        # to original and prepare for returning to caller
                        for i in range(len(evlist)):
                            evlist[i] = idx_xlat[evlist[i]]
                        err.errors.append(e)
                    else:
                        # Maybe transient error, prepare to try again
                        for evlist_i in evlist:
                            next_ev.append(ev[evlist_i])
                            next_idx_xlat.append(idx_xlat[evlist_i])
            ev = next_ev
            idx_xlat = next_idx_xlat
        # add the return value to the queue
        if q:
            q.put(self.log_err(err) if err.errors else {"saved": len(events)})
        return self.log_err(err) if err.errors else {"saved": len(events)}

    def getEvents(
        self,
        id=None,
        idstore=None,
        count=None,
        cat=None,
        nocat=None,
        tag=None,
        notag=None,
        group=None,
        nogroup=None,
    ):
        if not id:
            id = self._loadID(idstore)

        if res := self.sendRequest(
            "getEvents",
            id=id,
            count=count or self.get_events_limit,
            cat=cat,
            nocat=nocat,
            tag=tag,
            notag=notag,
            group=group,
            nogroup=nogroup,
        ):
            try:
                events = res["events"]
                newid = res["lastid"]
            except KeyError:
                events = Error(
                    method="getEvents",
                    message="Server returned bogus reply",
                    exc=exc_info(),
                    response=res,
                )
            self._saveID(newid)
        else:
            events = res

        return self.log_err(events)

    def close(self):
        if hasattr(self, "conn") and hasattr(self.conn, "close"):
            self.conn.close()

    __del__ = close


def format_time(
    year, month, day, hour, minute, second, microsec=0, utcoffset=None
):
    if utcoffset is None:
        utcoffset = -(time.altzone if time.daylight else time.timezone)
    tstr = "%04d-%02d-%02dT%02d:%02d:%02d" % (
        year,
        month,
        day,
        hour,
        minute,
        second,
    )
    usstr = "." + str(microsec).rstrip("0") if microsec else ""
    offsstr = (
        ("%+03d:%02d" % divmod((utcoffset + 30) // 60, 60))
        if utcoffset
        else "Z"
    )
    return tstr + usstr + offsstr


def read_cfg(cfgfile):
    with open(cfgfile, "r") as f:
        stripcomments = "\n".join(
            (l for l in f if not l.lstrip().startswith(("#", "//")))
        )
        return json.loads(stripcomments)
