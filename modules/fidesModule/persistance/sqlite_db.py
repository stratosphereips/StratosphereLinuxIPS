import sqlite3
import logging
from typing import List, Any, Optional
from ..model.peer import PeerInfo
from ..model.peer_trust_data import PeerTrustData
from ..model.recommendation import Recommendation
from ..model.recommendation_history import RecommendationHistory, RecommendationHistoryRecord
from ..model.service_history import ServiceHistoryRecord, ServiceHistory
from .. model.threat_intelligence import SlipsThreatIntelligence, ThreatIntelligence
from ..model.aliases import *
import threading

"""
Programmers notes:

Python has None, SQLite has NULL, conversion is automatic in both ways.
"""

class SQLiteDB:
    _lock = threading.Lock()

    def __init__(self, logger: logging.Logger, db_path: str) -> None:
        """
        Initializes the SQLiteDB instance, sets up logging, and connects to the database.

        :param logger: Logger for logging debug information.
        :param db_path: Path where the SQLite database will be stored.
        """
        self.logger = logger
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
        self.__connect()
        self.__create_tables()

    def get_peers_by_organisations(self, organisation_ids: List[str]) -> List[PeerInfo]:
        """
        Fetch PeerInfo records for peers that belong to at least one of the given organisations.
        Each peer will also have their associated organisations.

        :param organisation_ids: List of organisation IDs to filter peers by.
        :return: List of PeerInfo objects with associated organisation IDs.
        """
        placeholders = ','.join('?' for _ in organisation_ids)
        query = f"""
        SELECT P.peerID, P.ip, GROUP_CONCAT(PO.organisationID) as organisations
        FROM PeerInfo P
        JOIN PeerOrganisation PO ON P.peerID = PO.peerID
        WHERE PO.organisationID IN ({placeholders})
        GROUP BY P.peerID, P.ip;
        """

        results = self.__execute_query(query, organisation_ids)

        # Convert the result into a list of PeerInfo objects
        peers = []
        for row in results:
            peerID = row[0]
            ip = row[1]
            organisations = row[2].split(',') if row[2] else []
            peers.append(PeerInfo(id=peerID, organisations=organisations, ip=ip))

        return peers

    def insert_organisation_if_not_exists(self, organisation_id: OrganisationId) -> None:
        """
        Inserts an organisation into the Organisation table if it doesn't already exist.

        :param organisation_id: The organisation ID to insert.
        """
        query = "INSERT OR IGNORE INTO Organisation (organisationID) VALUES (?)"
        self.__execute_query(query, [organisation_id])

    def insert_peer_organisation_connection(self, peer_id: PeerId, organisation_id: OrganisationId) -> None:
        """
        Inserts a connection between a peer and an organisation in the PeerOrganisation table.

        :param peer_id: The peer's ID.
        :param organisation_id: The organisation's ID.
        """
        query = "INSERT OR IGNORE INTO PeerOrganisation (peerID, organisationID) VALUES (?, ?)"
        self.__execute_query(query, [peer_id, organisation_id])

    def store_connected_peers_list(self, peers: List[PeerInfo]) -> None:
        """
        Stores a list of PeerInfo instances into the database.

        :param peers: A list of PeerInfo instances to be stored.
        """

        peer_ids = [peer.id for peer in peers]  # Extract the peer IDs from list L
        placeholders = ','.join('?' for _ in peer_ids)
        delete_query = f"DELETE FROM PeerInfo WHERE peerID NOT IN ({placeholders})"
        self.__execute_query(delete_query, peer_ids)

        for peer_info in peers:
            peer = {
                'peerID': peer_info.id,
                'ip': peer_info.ip,
            }
            self.__insert_peer_info(peer_info)

            for organisation_id in peer_info.organisations:
                self.insert_organisation_if_not_exists(organisation_id)
                self.insert_peer_organisation_connection(peer_info.id, organisation_id)

    def get_connected_peers(self) -> List[PeerInfo]:
        """
        Retrieves a list of PeerInfo instances from the database, including associated organisations.

        :return: A list of PeerInfo instances.
        """
        # Step 1: Query the PeerInfo table to get all peer information
        peer_info_query = "SELECT peerID, ip FROM PeerInfo"
        peer_info_results = self.__execute_query(peer_info_query)

        peer_info_list = []

        # Step 2: For each peer, get the associated organisations from PeerOrganisation table
        for row in peer_info_results:
            peer_id = row[0]  # peerID is the first column
            ip = row[1]  # ip is the second column

            # Step 3: Get associated organisations from PeerOrganisation table
            organisations = self.get_peer_organisations(peer_id)

            # Step 4: Create the PeerInfo object and add to the list
            peer_info = PeerInfo(id=peer_id, organisations=organisations, ip=ip)
            peer_info_list.append(peer_info)

        return peer_info_list

    def get_peer_organisations(self, peer_id: PeerId) -> List[OrganisationId]:
        """
        Retrieves the list of organisations associated with a given peer from the PeerOrganisation table.

        :param peer_id: The peer's ID.
        :return: A list of Organisation IDs associated with the peer.
        """
        query = "SELECT organisationID FROM PeerOrganisation WHERE peerID = ?"
        results = self.__execute_query(query, [peer_id])

        # Extract organisationIDs from the query result and return as a list
        return [row[0] for row in results]

    def __insert_peer_trust_data(self, peer_trust_data: PeerTrustData) -> None:
        data = peer_trust_data.to_dict()
        self.__save('PeerTrustData', data)

    def __insert_recommendation_history(self, recommendation_record: RecommendationHistoryRecord) -> None:
        data = recommendation_record.to_dict()
        self.__save('RecommendationHistory', data)

    def __insert_service_history(self, service_record: ServiceHistoryRecord) -> None:
        data = service_record.to_dict()
        self.__save('ServiceHistory', data)

    def __insert_peer_info(self, peer_info: PeerInfo) -> None:
        data = peer_info.to_dict()
        self.__save('PeerInfo', data)

    def __connect(self) -> None:
        """
        Establishes a connection to the SQLite database.
        """
        self.logger.debug(f"Connecting to SQLite database at {self.db_path}")
        self.connection = sqlite3.connect(self.db_path)

    def __execute_query(self, query: str, params: Optional[List[Any]] = None) -> List[Any]:
        """
        Executes a given SQL query and returns the results.

        :param query: The SQL query to execute.
        :param params: Optional list of parameters for parameterized queries.
        :return: List of results returned from the executed query.
        """
        with SQLiteDB._lock:
            self.logger.debug(f"Executing query: {query}")
            cursor = self.connection.cursor()
            try:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                self.connection.commit()
                return cursor.fetchall()
            except Exception as e:
                self.logger.error(f"Error executing query: {e}")
                raise
            finally:
                cursor.close()  # Ensure the cursor is always closed

    def __save(self, table: str, data: dict) -> None:
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
        self.__execute_query(query, list(data.values()))

    def __delete(self, table: str, condition: str, params: Optional[List[Any]] = None) -> None:
        """
        Deletes rows from a table that match the condition.

        :param table: The table from which to delete the data.
        :param condition: A SQL condition for deleting rows (e.g., "id = ?").
        :param params: Optional list of parameters for parameterized queries.
        :return: None
        """
        query = f"DELETE FROM {table} WHERE {condition}"
        self.logger.debug(f"Deleting from table: {table} where {condition}")
        self.__execute_query(query, params)

    def __close(self) -> None:
        """
        Closes the SQLite database connection.
        """
        if self.connection:
            self.logger.debug("Closing database connection")
            self.connection.close()

    def __create_tables(self) -> None:
        """
        Creates the necessary tables in the SQLite database.
        """
        table_creation_queries = [
            """
            CREATE TABLE IF NOT EXISTS PeerInfo (
                peerID TEXT PRIMARY KEY,
                ip VARCHAR(39)
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
                FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID) ON DELETE CASCADE
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
                FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID) ON DELETE CASCADE
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
                FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID) ON DELETE CASCADE,
                FOREIGN KEY (organisationID) REFERENCES Organisation(organisationID) ON DELETE CASCADE
            );
            """
            
            """
            CREATE TABLE IF NOT EXISTS PeerTrustData (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peerID TEXT,                  -- The peer providing the trust evaluation
                has_fixed_trust INTEGER NOT NULL CHECK (is_active IN (0, 1)),   -- Whether the trust is dynamic or fixed
                service_trust REAL NOT NULL CHECK (service_trust >= 0.0 AND service_trust <= 1.0),  -- Service Trust Metric
                reputation REAL NOT NULL CHECK (reputation >= 0.0 AND reputation <= 1.0),           -- Reputation Metric
                recommendation_trust REAL NOT NULL CHECK (recommendation_trust >= 0.0 AND recommendation_trust <= 1.0), -- Recommendation Trust Metric
                competence_belief REAL NOT NULL CHECK (competence_belief >= 0.0 AND competence_belief <= 1.0),           -- Competence Belief
                integrity_belief REAL NOT NULL CHECK (integrity_belief >= 0.0 AND integrity_belief <= 1.0),               -- Integrity Belief
                initial_reputation_provided_by_count INTEGER NOT NULL,  -- Count of peers providing initial reputation
                FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID) ON DELETE CASCADE -- Delete trust data when PeerInfo is deleted
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS PeerTrustServiceHistory (
                peer_trust_data_id INTEGER,
                service_history_id INTEGER,
                PRIMARY KEY (peer_trust_data_id, service_history_id),
                FOREIGN KEY (peer_trust_data_id) REFERENCES PeerTrustData(id) ON DELETE CASCADE,
                FOREIGN KEY (service_history_id) REFERENCES ServiceHistory(id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS PeerTrustRecommendationHistory (
                peer_trust_data_id INTEGER,
                recommendation_history_id INTEGER,
                PRIMARY KEY (peer_trust_data_id, recommendation_history_id),
                FOREIGN KEY (peer_trust_data_id) REFERENCES PeerTrustData(id) ON DELETE CASCADE,
                FOREIGN KEY (recommendation_history_id) REFERENCES RecommendationHistory(id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS ThreatIntelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peerID TEXT,
                score FLOAT NOT NULL CHECK (score >= 0.0 AND score <= 1.0),
                confidence FLOAT NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
                target TEXT,
                confidentiality FLOAT CHECK (confidentiality >= 0.0 AND confidentiality <= 1.0),
                FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID) ON DELETE CASCADE
            );
            """
        ]

        for query in table_creation_queries:
            self.logger.debug(f"Creating tables with query: {query}")
            self.__execute_query(query)
