import sqlite3
import logging
from typing import List, Any, Optional


class SQLiteDB:
    def __init__(self, logger: logging.Logger, db_path: str) -> None:
        """
        Initializes the SQLiteDB instance, sets up logging, and connects to the database.

        :param logger: Logger for logging debug information.
        :param db_path: Path where the SQLite database will be stored.
        """
        self.logger = logger
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
        self.connect()

    def connect(self) -> None:
        """
        Establishes a connection to the SQLite database.
        """
        self.logger.debug(f"Connecting to SQLite database at {self.db_path}")
        self.connection = sqlite3.connect(self.db_path)

    def execute_query(self, query: str, params: Optional[List[Any]] = None) -> List[Any]:
        """
        Executes a given SQL query and returns the results.

        :param query: The SQL query to execute.
        :param params: Optional list of parameters for parameterized queries.
        :return: List of results returned from the executed query.
        """
        self.logger.debug(f"Executing query: {query}")
        cursor = self.connection.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        self.connection.commit()
        return cursor.fetchall()

    def save(self, table: str, data: dict) -> None:
        """
        Inserts or replaces data into a given table.

        :param table: The table in which to save the data.
        :param data: A dictionary where the keys are column names, and values are the values to be saved.
        :return: None
        """
        columns = ', '.join(data.keys())
        placeholders = ', '.join('?' * len(data))
        query = f"INSERT OR REPLACE INTO {table} ({columns}) VALUES ({placeholders})"
        self.logger.debug(f"Saving data: {data} into table: {table}")
        self.execute_query(query, list(data.values()))

    def delete(self, table: str, condition: str, params: Optional[List[Any]] = None) -> None:
        """
        Deletes rows from a table that match the condition.

        :param table: The table from which to delete the data.
        :param condition: A SQL condition for deleting rows (e.g., "id = ?").
        :param params: Optional list of parameters for parameterized queries.
        :return: None
        """
        query = f"DELETE FROM {table} WHERE {condition}"
        self.logger.debug(f"Deleting from table: {table} where {condition}")
        self.execute_query(query, params)

    def close(self) -> None:
        """
        Closes the SQLite database connection.
        """
        if self.connection:
            self.logger.debug("Closing database connection")
            self.connection.close()

    def create_tables(self) -> None:
        """
        Creates the necessary tables in the SQLite database.
        """
        table_creation_queries = [
            """
            CREATE TABLE IF NOT EXISTS PeerInfo (
                peerID TEXT PRIMARY KEY,
                ip VARCHAR(39) NOT NULL
                -- Add other attributes here (e.g., name TEXT, email TEXT, ...)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS ServiceHistory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peerID TEXT,
                satisfaction FLOAT NOT NULL  CHECK (satisfaction >= 0.0 AND satisfaction <= 1.0),
                weight FLOAT NOT NULL CHECK (weight >= 0.0 AND weight <= 1.0),
                service_time float NOT NULL,
                -- Add other attributes here (e.g., serviceDate DATE, serviceType TEXT)
                FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS RecommendationHistory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peerID TEXT,
                satisfaction FLOAT NOT NULL  CHECK (satisfaction >= 0.0 AND satisfaction <= 1.0),
                weight FLOAT NOT NULL CHECK (weight >= 0.0 AND weight <= 1.0),
                recommend_time FLOAT NOT NULL,
                -- Add other attributes here (e.g., recommendationDate DATE, recommendedBy TEXT, ...)
                FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS Organisation (
                organisationID TEXT PRIMARY KEY
                -- Add other attributes here (e.g., organisationName TEXT, location TEXT, ...)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS PeerOrganisation (
                peerID TEXT,
                organisationID TEXT,
                PRIMARY KEY (peerID, organisationID),
                FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID),
                FOREIGN KEY (organisationID) REFERENCES Organisation(organisationID)
            );
            """
            
            """
            CREATE TABLE PeerTrustData (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peerID VARCHAR(255),                  -- The peer providing the trust evaluation
                has_fixed_trust INTEGER NOT NULL CHECK (is_active IN (0, 1)),              -- Whether the trust is dynamic or fixed
                service_trust REAL NOT NULL CHECK (service_trust >= 0.0 AND service_trust <= 1.0),                   -- Service Trust Metric (0 <= service_trust <= 1)
                reputation REAL NOT NULL CHECK (reputation >= 0.0 AND reputation <= 1.0),                       -- Reputation Metric (0 <= reputation <= 1)
                recommendation_trust REAL NOT NULL CHECK (recommendation_trust >= 0.0 AND recommendation_trust <= 1.0),            -- Recommendation Trust Metric (0 <= recommendation_trust <= 1)
                competence_belief REAL NOT NULL CHECK (competence_belief >= 0.0 AND competence_belief <= 1.0),               -- Competence Belief (0 <= competence_belief <= 1)
                integrity_belief REAL NOT NULL CHECK (integrity_belief >= 0.0 AND integrity_belief <= 1.0),                -- Integrity Belief (0 <= integrity_belief <= 1)
                initial_reputation_provided_by_count INTEGER NOT NULL,  -- Count of peers providing initial reputation
                service_history_id INTEGER,            -- Reference to ServiceHistory (could be NULL if not applicable)
                recommendation_history_id INTEGER,     -- Reference to RecommendationHistory (could be NULL if not applicable)
                FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID),
                FOREIGN KEY (service_history_id) REFERENCES ServiceHistory(id),
                FOREIGN KEY (recommendation_history_id) REFERENCES RecommendationHistory(id)
            );
            """
        ]

        for query in table_creation_queries:
            self.logger.debug(f"Creating tables with query: {query}")
            self.execute_query(query)


if __name__ == "__main__":
    # Step 1: Set up a logger
    logger = logging.getLogger('my_logger')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    # Step 2: Create SQLiteDB instance
    db = SQLiteDB(logger, "test.db")

    # Step 3: Create a table
    db.execute_query("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)")

    # Step 4: Insert data using the save method
    db.save("users", {"id": 1, "name": "John", "age": 30})
    db.save("users", {"id": 2, "name": "Jane", "age": 25})

    # Step 5: Retrieve and print data
    results = db.execute_query("SELECT * FROM users")
    logger.debug(f"Users: {results}")

    # Step 6: Delete a user using the delete method
    db.delete("users", "id = ?", [1])

    # Step 7: Print data after deletion
    results = db.execute_query("SELECT * FROM users")
    logger.debug(f"Users after deletion: {results}")

    # Step 8: Close the database connection
    db.close()
