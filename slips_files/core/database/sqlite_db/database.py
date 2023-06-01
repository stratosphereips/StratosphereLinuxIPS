import os.path
import sqlite3
import json
from dataclasses import asdict


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

    @classmethod
    def create_table(cls, table_name, schema):
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({schema})"
        cls.cursor.execute(query)
        cls.conn.commit()

    def set_flow_label(self, uids: list, new_label: str):
        """
        sets the given new_label to each flow in the uids list
        """
        for uid in uids:
            query = f'UPDATE flows SET label="{new_label}" WHERE uid="{uid}"'
            try:
                self.conn.execute(
                    query
                )
                self.conn.commit()
            except sqlite3.Error as e:
                # An error occurred during execution
                print(f"Error executing query ({query}): {e}")

    def get_flow(self, uid: str, twid=False) -> dict:
        """
        Returns the flow with the given uid
        the flow returned is read from conn.log
        """
        condition = f'uid = "{uid}"'
        if twid:
            condition += f', twid = "{twid}"'

        res = self.select('flows', condition=condition)
        res = res[0][1] if res else {}
        return {uid: res}

    def add_flow(
            self, flow, profileid: str, twid:str, label='benign'
            ):

        parameters = (profileid, twid, flow.uid, json.dumps(asdict(flow)), label)
        self.cursor.execute(
            'INSERT INTO flows (profileid, twid, uid, flow, label) '
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
        self.cursor.execute(query)
        result = self.cursor.fetchall()
        return result

    def execute_query(self, query):
        self.cursor.execute(query)
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()
