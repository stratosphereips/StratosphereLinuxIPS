# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from datetime import datetime
from typing import List, Dict
import os.path
import sqlite3
import json
import csv
from dataclasses import asdict

from slips_files.common.abstracts.isqlite import ISQLite
from slips_files.common.printer import Printer
from slips_files.common.slips_utils import utils
from slips_files.core.structures.alerts import Alert
from slips_files.core.output import Output


class SQLiteDB(ISQLite):
    """
    Stores all the flows slips reads and handles labeling them
    Creates a new db and connects to it if there's none in the given output_dir
    """

    name = "SQLiteDB"

    def __init__(self, logger: Output, output_dir: str, main_pid: int):
        self.printer = Printer(logger, self.name)
        self._flows_db = os.path.join(output_dir, "flows.sqlite")

        db_newly_created = False
        if not os.path.exists(self._flows_db):
            # db not created, mark it as first time accessing it so we can
            # init tables once we connect
            db_newly_created = True
            self._init_db()
        # connects to the db
        super().__init__(self.name.lower(), main_pid, self._flows_db)

        if db_newly_created:
            # only init tables if the db is newly created
            self.init_tables()

    def init_tables(self):
        """creates the tables we're gonna use"""
        table_schema = {
            "flows": "uid TEXT PRIMARY KEY, flow TEXT, label TEXT, profileid "
            "TEXT, twid TEXT, aid TEXT",
            "altflows": "uid TEXT PRIMARY KEY, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, flow_type TEXT",
            "alerts": "alert_id TEXT PRIMARY KEY, alert_time TEXT, ip_alerted "
            "TEXT, timewindow TEXT, tw_start TEXT, tw_end TEXT, "
            "label TEXT",
        }
        for table_name, schema in table_schema.items():
            self.create_table(table_name, schema)

    def _init_db(self):
        """
        creates the db if it doesn't exist and clears it if it exists
        """
        # make it accessible to root and non-root users, because when
        # slips is started using sudo, it drops privs from modules that
        # don't need them, and without this line, these modules wont be
        # able to access the path_to_remote_ti_files
        open(self._flows_db, "w").close()
        os.chmod(self._flows_db, 0o777)

    def get_db_path(self) -> str:
        """
        returns the path of the sqlite flows db placed in the output dir
        """
        return self._flows_db

    def get_altflow_from_uid(self, profileid, twid, uid) -> dict:
        """Given a uid, get the alternative flow associated with it"""
        condition = f'uid = "{uid}"'
        altflow = self.select("altflows", condition=condition)
        if altflow:
            flow: str = altflow[0][1]
            return json.loads(flow)
        return False

    def get_all_contacted_ips_in_profileid_twid(self, profileid, twid) -> dict:
        all_flows: dict = self.get_all_flows_in_profileid_twid(profileid, twid)

        if not all_flows:
            return {}

        contacted_ips = {}
        for uid, flow in all_flows.items():
            # get the daddr of this flow
            daddr = flow["daddr"]
            contacted_ips[daddr] = uid
        return contacted_ips

    def get_all_flows_in_profileid_twid(self, profileid, twid):
        condition = f'profileid = "{profileid}" ' f'AND twid = "{twid}"'
        all_flows: list = self.select("flows", condition=condition)
        if not all_flows:
            return False
        res = {}
        for flow in all_flows:
            uid = flow[0]
            flow = flow[1]
            res[uid] = json.loads(flow)
        return res

    def get_all_flows_in_profileid(self, profileid) -> Dict[str, dict]:
        """
        Return a list of all the flows in this profileid
        [{'uid':flow},...]
        """
        condition = f'profileid = "{profileid}"'
        flows = self.select("flows", condition=condition)
        all_flows: Dict[str, dict] = {}
        if flows:
            for flow in flows:
                uid = flow[0]
                flow: str = flow[1]
                all_flows[uid] = json.loads(flow)

        return all_flows

    def get_all_flows(self):
        """
        Returns a list with all the flows in all profileids and twids
        Each element in the list is a flow
        """
        flows = self.select("flows")
        flow_list = []
        if flows:
            for flow in flows:
                flow_list.append(json.loads(flow[1]))
        return flow_list

    def set_flow_label(self, uids: List[str], new_label: str):
        """
        sets the given new_label to each flow in the uids list
        """
        for uid in uids:
            # add the label to the flow (conn.log flow)
            query = f'UPDATE flows SET label="{new_label}" WHERE uid="{uid}"'
            self.execute(query)
            # add the label to the altflow (dns, http, whatever it is)
            query = (
                f'UPDATE altflows SET label="{new_label}" WHERE uid="{uid}"'
            )
            self.execute(query)

    def export_labeled_flows(self, output_dir, format):
        if "tsv" in format:
            csv_output_file = os.path.join(output_dir, "labeled_flows.tsv")
            header: list = self.get_columns("flows")

            with open(csv_output_file, "w", newline="") as tsv_file:
                writer = csv.writer(tsv_file, delimiter="\t")

                # write the header
                writer.writerow(header)

                # Fetch rows one by one and write them to the file
                for row in self.iterate_flows():
                    writer.writerow(row)

        if "json" in format:
            json_output_file = os.path.join(output_dir, "labeled_flows.json")

            with open(json_output_file, "w", newline="") as json_file:
                # Fetch rows one by one and write them to the file
                for row in self.iterate_flows():
                    json_labeled_flow = {
                        "uid": row[0],
                        "flow": row[1],
                        "label": row[2],
                        "profileid": row[3],
                        "twid": row[4],
                    }
                    json.dump(json_labeled_flow, json_file)
                    json_file.write("\n")

    def get_columns(self, table) -> list:
        """returns a list with column names in the given table"""
        self.execute(f"PRAGMA table_info({table})")
        columns = self.fetchall()
        return [column[1] for column in columns]

    def iterate_flows(self):
        """returns an iterator"""

        # generator function to iterate over the rows
        def row_generator():
            # select all flows and altflows
            self.execute(
                "SELECT * FROM flows UNION SELECT uid, flow, label, profileid,"
                " twid FROM altflows"
            )

            while True:
                row = self.fetchone()
                if row is None:
                    break
                yield row

        # Return the combined iterator
        return iter(row_generator())

    def get_flow(self, uid: str, twid=False) -> dict:
        """
        Returns the flow with the given uid
        the flow returned is read from conn.log
        """
        condition = f'uid = "{uid}"'
        if twid:
            condition += f'AND twid = "{twid}"'

        res = self.select("flows", condition=condition)
        res = res[0][1] if res else {}
        return {uid: res}

    def add_flow(self, flow, profileid: str, twid: str, label="benign"):
        if hasattr(flow, "aid"):
            parameters = (
                profileid,
                twid,
                flow.uid,
                json.dumps(asdict(flow)),
                label,
                flow.aid,
            )
            self.execute(
                "INSERT OR REPLACE INTO flows (profileid, twid, uid, flow, label, aid) "
                "VALUES (?, ?, ?, ?, ?, ?);",
                parameters,
            )
        else:
            parameters = (
                profileid,
                twid,
                flow.uid,
                json.dumps(asdict(flow)),
                label,
            )

            self.execute(
                "INSERT OR REPLACE INTO flows (profileid, twid, uid, flow, label) "
                "VALUES (?, ?, ?, ?, ?);",
                parameters,
            )

    def get_flows_count(self, profileid=None, twid=None) -> int:
        """
        returns the total number of flows
         in the db for this profileid and twid if given
        """
        condition = ""
        if profileid:
            condition = f'profileid="{profileid}"'
        elif twid and not profileid:
            condition += f'twid= "{twid}"'
        elif profileid and twid:
            condition += f'AND twid= "{twid}"'

        flows = self.get_count("flows", condition=condition)
        # flows += self.get_count('altflows', condition=condition)
        return flows

    def add_altflow(self, flow, profileid: str, twid: str, label="benign"):
        parameters = (
            profileid,
            twid,
            flow.uid,
            json.dumps(asdict(flow)),
            label,
            flow.type_,
        )
        self.execute(
            "INSERT OR REPLACE INTO altflows (profileid, twid, uid, "
            "flow, label, flow_type) "
            "VALUES (?, ?, ?, ?, ?, ?);",
            parameters,
        )

    def add_alert(self, alert: Alert):
        """
        adds an alert to the alerts table
        """
        now = utils.convert_ts_format(datetime.now(), "unixtimestamp")
        self.execute(
            "INSERT OR REPLACE INTO alerts "
            "(alert_id, ip_alerted, timewindow, tw_start, tw_end, label, alert_time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?);",
            (
                alert.id,
                alert.profile.ip,
                str(alert.timewindow),
                alert.timewindow.start_time,
                alert.timewindow.end_time,
                "malicious",
                # This is the local time slips detected this alert, not the
                # network time
                now,
            ),
        )
