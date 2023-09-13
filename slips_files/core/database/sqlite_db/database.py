import os.path
import sqlite3
import json
import csv
from dataclasses import asdict
from threading import Lock
from time import sleep

class SQLiteDB():
    """Stores all the flows slips reads and handles labeling them"""
    name = "SQLiteDB"
    # used to lock each call to commit()
    cursor_lock = Lock()
    trial = 0

    def __init__(self, output_dir, output_queue):
        self.output_queue = output_queue
        self._flows_db = os.path.join(output_dir, 'flows.sqlite')
        self.connect()

    def connect(self):
        """
        Creates the db if it doesn't exist and connects to it
        """
        db_newly_created = False
        if not os.path.exists(self._flows_db):
            # db not created, mark it as first time accessing it so we can init tables once we connect
            db_newly_created = True
            self._init_db()

        self.conn = sqlite3.connect(self._flows_db, check_same_thread=False, timeout=20)

        self.cursor = self.conn.cursor()
        if db_newly_created:
            # only init tables if the db is newly created
            self.init_tables()

    def get_number_of_tables(self):
        """
        returns the number of tables in the current db
        """
        query = f"SELECT count(*) FROM sqlite_master WHERE type='table';"
        self.execute(query)
        x = self.fetchone()
        return x[0]

    def init_tables(self):
        """creates the tables we're gonna use"""
        table_schema = {
            'flows': "uid TEXT PRIMARY KEY, flow TEXT, label TEXT, profileid TEXT, twid TEXT, aid TEXT",
            'altflows': "uid TEXT PRIMARY KEY, flow TEXT, label TEXT, profileid TEXT, twid TEXT, flow_type TEXT",
            'alerts': 'alert_id TEXT PRIMARY KEY, alert_time TEXT, ip_alerted TEXT, timewindow TEXT, tw_start TEXT, tw_end TEXT, label TEXT'
            }
        for table_name, schema in table_schema.items():
            self.create_table(table_name, schema)

    def _init_db(self):
        """
        creates the db if it doesn't exist and clears it if it exists
        """
        open(self._flows_db,'w').close()

    def create_table(self, table_name, schema):
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({schema})"
        self.execute(query)

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """
        levels = f'{verbose}{debug}'
        try:
            self.output_queue.put(f'{levels}|{self.name}|{text}')
        except AttributeError:
            pass

    def get_db_path(self) -> str:
        """
        returns the path of the sqlite flows db placed in the output dir
        """
        return self._flows_db


    def get_altflow_from_uid(self, profileid, twid, uid) -> dict:
        """ Given a uid, get the alternative flow associated with it """
        condition = f'uid = "{uid}"'
        altflow = self.select('altflows', condition=condition)
        if altflow:
            flow: str = altflow[0][1]
            return json.loads(flow)
        return False

    def get_all_contacted_ips_in_profileid_twid(self, profileid, twid) -> dict:
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return {}
        all_flows: dict = self.get_all_flows_in_profileid_twid(profileid, twid)

        if not all_flows:
            return {}

        contacted_ips = {}
        for uid, flow in all_flows.items():
            # get the daddr of this flow
            daddr = flow['daddr']
            contacted_ips[daddr] = uid
        return contacted_ips


    def get_all_flows_in_profileid_twid(self, profileid, twid):
        condition = f'profileid = "{profileid}" ' \
                    f'AND twid = "{twid}"'
        all_flows: list = self.select('flows', condition=condition)
        if not all_flows:
            return False
        res = {}
        for flow in all_flows:
            uid = flow[0]
            flow = flow[1]
            res[uid] = json.loads(flow)
        return res

    def get_all_flows_in_profileid(self, profileid):
        """
        Return a list of all the flows in this profileid
        [{'uid':flow},...]
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return []

        condition = f'profileid = "{profileid}"'
        flows = self.select('flows', condition=condition)
        all_flows = {}
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
        flows = self.select('flows')
        flow_list = []
        if flows:
            for flow in flows:
                flow_list.append(json.loads(flow[1]))
        return flow_list

    def set_flow_label(self, uids: list, new_label: str):
        """
        sets the given new_label to each flow in the uids list
        """
        for uid in uids:
            # add the label to the flow (conn.log flow)
            query = f'UPDATE flows SET label="{new_label}" WHERE uid="{uid}"'
            self.execute(query)
            # add the label to the altflow (dns, http, whatever it is)
            query = f'UPDATE altflows SET label="{new_label}" WHERE uid="{uid}"'
            self.execute(query)

    def export_labeled_flows(self, output_dir, format):
        if 'tsv' in format:
            csv_output_file = os.path.join(output_dir, 'labeled_flows.tsv')
            header: list = self.get_columns('flows')

            with open(csv_output_file, 'w', newline='') as tsv_file:
                writer = csv.writer(tsv_file, delimiter='\t')

                # write the header
                writer.writerow(header)

                # Fetch rows one by one and write them to the file
                for row in self.iterate_flows():
                    writer.writerow(row)

        if 'json' in format:
            json_output_file = os.path.join(output_dir, 'labeled_flows.json')

            with open(json_output_file, 'w', newline='') as json_file:
                # Fetch rows one by one and write them to the file
                for row in self.iterate_flows():
                    json_labeled_flow = {
                        'uid': row[0],
                        'flow': row[1],
                        'label': row[2],
                        'profileid': row[3],
                        'twid': row[4],
                        }
                    json.dump(json_labeled_flow, json_file)
                    json_file.write('\n')

    def get_columns(self, table) -> list:
        """returns a list with column names in the given table"""
        self.execute(f"PRAGMA table_info({table})")
        columns = self.fetchall()
        return [column[1] for column in columns]

    def iterate_flows(self):
        """returns an iterator """
        # generator function to iterate over the rows
        def row_generator():
            # select all flows and altflows
            self.execute('SELECT * FROM flows UNION SELECT uid, flow, label, profileid, twid FROM altflows')

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

        res = self.select('flows', condition=condition)
        res = res[0][1] if res else {}
        return {uid: res}

    def add_flow(
            self, flow, profileid: str, twid:str, label='benign'
            ):
        if hasattr(flow, 'aid'):
            parameters = (profileid, twid, flow.uid, json.dumps(asdict(flow)), label, flow.aid)
            self.execute(
                'INSERT OR REPLACE INTO flows (profileid, twid, uid, flow, label, aid) '
                'VALUES (?, ?, ?, ?, ?, ?);',
                parameters,
            )
        else:
            parameters = (profileid, twid, flow.uid, json.dumps(asdict(flow)), label)

            self.execute(
                'INSERT OR REPLACE INTO flows (profileid, twid, uid, flow, label) '
                'VALUES (?, ?, ?, ?, ?);',
                parameters,
            )

    def get_flows_count(self, profileid, twid) -> int:
        """
        returns the total number of flows AND altflows
         in the db for this profileid and twid
         """
        condition = f'profileid="{profileid}" AND twid= "{twid}"'
        flows = self.get_count('flows', condition=condition)
        flows += self.get_count('altflows', condition=condition)
        return flows


    def add_altflow(
            self, flow, profileid: str, twid:str, label='benign'
            ):
        parameters = (profileid, twid, flow.uid, json.dumps(asdict(flow)), label, flow.type_)
        self.execute(
            'INSERT OR REPLACE INTO altflows (profileid, twid, uid, flow, label, flow_type) '
            'VALUES (?, ?, ?, ?, ?, ?);',
            parameters,
        )

    def add_alert(self, alert: dict):
        """
        adds an alert to the alerts table
        alert param should contain alert_id, alert_ts, ip_alerted, twid, tw_start, tw_end, label
        """
        # 'alerts': 'alert_id TEXT PRIMARY KEY, alert_time TEXT, ip_alerted TEXT, timewindow TEXT, tw_start TEXT, tw_end TEXT, label TEXT'
        self.execute(
            'INSERT OR REPLACE INTO alerts (alert_id, ip_alerted, timewindow, tw_start, tw_end, label, alert_time) '
            'VALUES (?, ?, ?, ?, ?, ?, ?);',
            (alert['alert_ID'],
             alert['profileid'].split()[-1],
             alert['twid'],
             alert['tw_start'],
             alert['tw_end'],
             alert['label'],
             alert['time_detected'])
        )



    def insert(self, table_name, values):
        query = f"INSERT INTO {table_name} VALUES ({values})"
        self.execute(query)


    def update(self, table_name, set_clause, condition):
        query = f"UPDATE {table_name} SET {set_clause} WHERE {condition}"
        self.execute(query)


    def delete(self, table_name, condition):
        query = f"DELETE FROM {table_name} WHERE {condition}"
        self.execute(query)


    def select(self, table_name, columns="*", condition=None):
        query = f"SELECT {columns} FROM {table_name}"
        if condition:
            query += f" WHERE {condition}"
        self.execute(query)
        result = self.fetchall()
        return result

    def get_count(self, table, condition=None):
        """
        returns th enumber of matching rows in the given table based on a specific contioins
        """
        query = f"SELECT COUNT(*) FROM {table}"

        if condition:
            query += f" WHERE {condition}"

        self.execute(query)
        return self.fetchone()[0]


    def close(self):
        self.cursor.close()
        self.conn.close()

    def fetchall(self):
        """
        wrapper for sqlite fetchall to be able to use a lock
        """
        self.cursor_lock.acquire(True)
        res = self.cursor.fetchall()
        self.cursor_lock.release()
        return res


    def fetchone(self):
        """
        wrapper for sqlite fetchone to be able to use a lock
        """
        self.cursor_lock.acquire(True)
        res = self.cursor.fetchone()
        self.cursor_lock.release()
        return res    
    
    def execute(self, query, params=None):
        """
        wrapper for sqlite execute() To avoid 'Recursive use of cursors not allowed' error
        and to be able to use a Lock()
        since sqlite is terrible with multi-process applications
        this should be used instead of all calls to commit() and execute()
        """
        try:
            self.cursor_lock.acquire(True)
            #start a transaction
            self.cursor.execute('BEGIN')

            if not params:
                self.cursor.execute(query)
            else:
                self.cursor.execute(query, params)

            self.conn.commit()

            self.cursor_lock.release()
            # counter for the number of times we tried executing a tx and failed
            self.trial = 0

        except sqlite3.Error as e:
            self.cursor_lock.release()
            self.conn.rollback()
            if self.trial >= 2:
                # tried 2 times to exec a query and it's still failing
                self.trial = 0
                # discard query
                self.print(f"Error executing query: {query} - {e}. Query discarded", 0, 1)

            elif "database is locked" in str(e):
                # keep track of failed trials
                self.trial += 1

                # Retry after a short delay
                sleep(5)
                self.execute(query, params=params)
            else:
                # An error occurred during execution
                self.conn.rollback()
                # print(f"Re-trying to execute query ({query}). reason: {e}")
                # keep track of failed trials
                self.trial += 1
                self.execute(query, params=params)



        