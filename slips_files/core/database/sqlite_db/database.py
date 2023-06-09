import os.path
import sqlite3
import json
import csv
from dataclasses import asdict
from threading import Lock

class SQLiteDB():
    """Stores all the flows slips reads and handles labeling them"""
    _obj = None

    def __new__(cls, output_dir):
        # To treat the db as a singelton
        if cls._obj is None or not isinstance(cls._obj, cls):
            cls._obj = super(SQLiteDB, cls).__new__(SQLiteDB)
            cls._flows_db = os.path.join(output_dir, 'flows.sqlite')
            cls._init_db()
            cls.conn = sqlite3.connect(cls._flows_db, check_same_thread=False)
            cls.cursor = cls.conn.cursor()
            cls.init_tables()
            cls.cursor_lock = Lock()
        return cls._obj


    @classmethod
    def init_tables(cls):
        """creates the tables we're gonna use"""
        table_schema = {
            'flows': "uid TEXT PRIMARY KEY, flow TEXT, label TEXT, profileid TEXT, twid TEXT",
            'altflows': "uid TEXT PRIMARY KEY, flow TEXT, label TEXT, profileid TEXT, twid TEXT"
            }
        for table_name, schema in table_schema.items():
            cls.create_table(table_name, schema)

    @classmethod
    def _init_db(cls):
        """
        creates the db if it doesn't exist and clears it if it exists
        """
        open(cls._flows_db,'w').close()

    def get_db_path(self) -> str:
        """
        returns the path of the sqlite flows db placed in the output dir
        """
        return self._flows_db

    @classmethod
    def create_table(cls, table_name, schema):
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({schema})"
        cls.cursor.execute(query)
        cls.conn.commit()

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
            query = f'UPDATE flows SET label="{new_label}" WHERE uid="{uid}"'
            try:
                self.cursor.execute(
                    query
                )
                self.conn.commit()
            except sqlite3.Error as e:
                # An error occurred during execution
                print(f"Error executing query ({query}): {e}")
    
    def export_labeled_flows(self, output_dir, format):
        if 'csv' in format:
            csv_output_file = os.path.join(output_dir, 'labeled_flows.csv')
            header: list = self.get_columns('flows')

            with open(csv_output_file, 'w', newline='') as csv_file:
                csv_writer = csv.writer(csv_file)

                # write the header
                csv_writer.writerow(header)

                # Fetch rows one by one and write them to the file
                for row in self.iterate_flows():
                    csv_writer.writerow(row)

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
        self.cursor.execute(f"PRAGMA table_info({table})")
        columns = self.cursor.fetchall()
        return [column[1] for column in columns]

    def iterate_flows(self):
        """returns an iterator """
        # generator function to iterate over the rows
        def row_generator():
            # select all flows and altflows
            self.cursor.execute('SELECT * FROM flows UNION SELECT * FROM altflows')

            while True:
                row = self.cursor.fetchone()
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

        parameters = (profileid, twid, flow.uid, json.dumps(asdict(flow)), label)
        self.cursor.execute(
            'INSERT OR REPLACE INTO flows (profileid, twid, uid, flow, label) '
            'VALUES (?, ?, ?, ?, ?);',
            parameters,
        )
        self.conn.commit()

    def add_altflow(
            self, flow, profileid: str, twid:str, label='benign'
            ):
        parameters = (profileid, twid, flow.uid, json.dumps(asdict(flow)), label)
        self.cursor.execute(
            'INSERT OR REPLACE INTO altflows (profileid, twid, uid, flow, label) '
            'VALUES (?, ?, ?, ?, ?);',
            parameters,
        )
        self.conn.commit()


    def insert(self, table_name, values):
        query = f"INSERT INTO {table_name} VALUES ({values})"
        self.cursor.execute(query)
        self.conn.commit()

    def update(self, table_name, set_clause, condition):
        query = f"UPDATE {table_name} SET {set_clause} WHERE {condition}"
        self.cursor.execute(query)
        self.conn.commit()

    def delete(self, table_name, condition):
        query = f"DELETE FROM {table_name} WHERE {condition}"
        self.cursor.execute(query)
        self.conn.commit()

    def select(self, table_name, columns="*", condition=None):
        query = f"SELECT {columns} FROM {table_name}"
        if condition:
            query += f" WHERE {condition}"
        self.cursor_lock.acquire(True)
        self.cursor.execute(query)
        result = self.cursor.fetchall()
        self.cursor_lock.release()
        return result

    def execute_query(self, query):
        self.cursor.execute(query)
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()
