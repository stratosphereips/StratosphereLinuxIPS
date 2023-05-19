import sqlite3

class SQLite():
    _obj = None

    def __new__(cls, *args, **kwargs):
        if cls._obj is None or not isinstance(cls._obj, cls):
            cls._obj = super(SQLite, cls).__new__(SQLite)
            db_name = args[0]
            cls.conn = sqlite3.connect(db_name)
            cls.cursor = cls.conn.cursor()

        # To treat the db as a singelton
        return cls._obj


    def create_table(self, table_name, schema):
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({schema})"
        self.cursor.execute(query)
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
