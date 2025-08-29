"""
Programmers notes:

Python has None, SQLite has NULL, conversion is automatic in both ways.
"""

import os
import sqlite3
from typing import List, Any, Optional

from slips_files.core.output import Output
from ..model.peer import PeerInfo
from ..model.peer_trust_data import PeerTrustData
from ..model.recommendation_history import RecommendationHistoryRecord
from ..model.service_history import ServiceHistoryRecord
from ..model.threat_intelligence import SlipsThreatIntelligence
from ..model.aliases import *
import threading


class SQLiteDB:
    _lock = threading.RLock()
    name = "Fides SQLiteDB"

    def __init__(self, logger: Output, db_path: str) -> None:
        """
        Initializes the SQLiteDB instance, sets up logging, and connects to the database.

        :param logger: Logger for logging debug information.
        :param db_path: Path where the SQLite database will be stored.
        """
        self.logger = logger
        self.db_path = db_path
        with open(self.db_path, "a") as f:
            f.close()
        sqlite3.connect(self.db_path).close()
        self.connection: Optional[sqlite3.Connection] = None
        self.__connect()
        self.__create_tables()

    def __slips_log(self, txt: str) -> None:
        self.logger.output_line_to_cli_and_logfiles(
            {"verbose": 2, "debug": 0, "from": self.name, "txt": txt}
        )

    def get_slips_threat_intelligence_by_target(
        self, target: Target
    ) -> Optional[SlipsThreatIntelligence]:
        """
        Retrieves a SlipsThreatIntelligence record by its target.

        :param target: The target (IP address, domain, etc.) of the intelligence.
        :return: A SlipsThreatIntelligence instance or None if not found.
        """
        query = """
        SELECT score, confidence, target, confidentiality
        FROM ThreatIntelligence
        WHERE target = ?;
        """

        # Execute the query to get the result
        rows = self.__execute_query(query, [target])

        if rows:
            score, confidence, target, confidentiality = rows[0]
            return SlipsThreatIntelligence(
                score=score,
                confidence=confidence,
                target=target,
                confidentiality=confidentiality,
            )

        return None

    def store_slips_threat_intelligence(
        self, intelligence: SlipsThreatIntelligence
    ) -> None:
        """
        Stores or updates the given SlipsThreatIntelligence object in the database based on the target.

        :param intelligence: The SlipsThreatIntelligence object to store or update.
        """
        query = """
        INSERT INTO ThreatIntelligence (
            target, score, confidence, confidentiality
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT(target) DO UPDATE SET
            score = excluded.score,
            confidence = excluded.confidence,
            confidentiality = excluded.confidentiality;
        """

        # Convert the confidentiality to None if not provided, and flatten data for insertion
        params = [
            intelligence.target,
            intelligence.score,
            intelligence.confidence,
            intelligence.confidentiality,
        ]

        # Execute the query
        self.__execute_query(query, params)

    def store_peer_trust_data(self, peer_trust_data: PeerTrustData) -> None:
        with SQLiteDB._lock:
            # Insert PeerInfo first to ensure the peer exists
            self.__execute_query(
                """
                INSERT OR REPLACE INTO PeerInfo (peerID, ip)
                VALUES (?, ?);
            """,
                (peer_trust_data.info.id, peer_trust_data.info.ip),
            )

            # Insert organisations for the peer into the PeerOrganisation table
            for org_id in peer_trust_data.info.organisations:
                self.__execute_query(
                    """
                    INSERT OR REPLACE INTO PeerOrganisation (peerID, organisationID)
                    VALUES (?, ?);
                """,
                    (peer_trust_data.info.id, org_id),
                )

            # Insert PeerTrustData itself
            self.__execute_query(
                """
                INSERT INTO PeerTrustData (
                    peerID, has_fixed_trust, service_trust, reputation, recommendation_trust,
                    competence_belief, integrity_belief, initial_reputation_provided_by_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
                (
                    peer_trust_data.info.id,
                    int(peer_trust_data.has_fixed_trust),
                    peer_trust_data.service_trust,
                    peer_trust_data.reputation,
                    peer_trust_data.recommendation_trust,
                    peer_trust_data.competence_belief,
                    peer_trust_data.integrity_belief,
                    peer_trust_data.initial_reputation_provided_by_count,
                ),
            )

            # Prepare to insert service history and link to PeerTrustData
            for sh in peer_trust_data.service_history:
                self.__execute_query(
                    """
                    INSERT INTO ServiceHistory (peerID, satisfaction, weight, service_time)
                    VALUES (?, ?, ?, ?);
                """,
                    (
                        peer_trust_data.info.id,
                        sh.satisfaction,
                        sh.weight,
                        sh.timestamp,
                    ),
                )

                # Insert into PeerTrustServiceHistory
                self.__execute_query(
                    """
                    INSERT INTO PeerTrustServiceHistory (peer_trust_data_id, service_history_id)
                    VALUES (last_insert_rowid(), last_insert_rowid());
                """
                )

            # Prepare to insert recommendation history and link to PeerTrustData
            for rh in peer_trust_data.recommendation_history:
                self.__execute_query(
                    """
                    INSERT INTO RecommendationHistory (peerID, satisfaction, weight, recommend_time)
                    VALUES (?, ?, ?, ?);
                """,
                    (
                        peer_trust_data.info.id,
                        rh.satisfaction,
                        rh.weight,
                        rh.timestamp,
                    ),
                )

                # Insert into PeerTrustRecommendationHistory
                self.__execute_query(
                    """
                    INSERT INTO PeerTrustRecommendationHistory (peer_trust_data_id, recommendation_history_id)
                    VALUES (last_insert_rowid(), last_insert_rowid());
                """
                )

    def get_peers_by_minimal_recommendation_trust(
        self, minimal_recommendation_trust: float
    ) -> List[PeerInfo]:
        # SQL query to select PeerInfo of peers that meet the minimal recommendation_trust criteria
        query = """
        SELECT pi.peerID, pi.ip
        FROM PeerTrustData ptd
        JOIN PeerInfo pi ON ptd.peerID = pi.peerID
        WHERE ptd.recommendation_trust >= ?;
        """

        # Execute the query, passing the minimal_recommendation_trust as a parameter
        result_rows = self.__execute_query(
            query, [minimal_recommendation_trust]
        )

        peer_list = []
        for row in result_rows:
            peer_id = row[0]
            ip = row[1]

            # Get the organisations for the peer using the get_peer_organisations method below
            organisations = self.get_peer_organisations(peer_id)

            # Create a PeerInfo instance with the retrieved organisations and IP
            peer_info = PeerInfo(
                id=peer_id, organisations=organisations, ip=ip
            )
            peer_list.append(peer_info)

        return peer_list

    def get_peer_trust_data(self, peer_id: str) -> PeerTrustData:
        # Fetch PeerTrustData along with PeerInfo
        query_peer_trust = """
        SELECT ptd.*, pi.peerID, pi.ip
        FROM PeerTrustData ptd
        JOIN PeerInfo pi ON ptd.peerID = pi.peerID
        WHERE ptd.peerID = ?;
        """
        peer_trust_row = self.__execute_query(query_peer_trust, [peer_id])

        # If no result found, return None
        if not peer_trust_row:
            return None

        peer_trust_row = peer_trust_row[
            0
        ]  # Get the first row (since fetchall() returns a list of rows)

        # Unpack PeerTrustData row (adjust indices based on your column order)
        (
            trust_data_id,
            peerID,
            has_fixed_trust,
            service_trust,
            reputation,
            recommendation_trust,
            competence_belief,
            integrity_belief,
            initial_reputation_count,
            _,
            ip,
        ) = peer_trust_row

        # Fetch ServiceHistory for the peer
        query_service_history = """
        SELECT sh.satisfaction, sh.weight, sh.service_time
        FROM ServiceHistory sh
        JOIN PeerTrustServiceHistory pts ON sh.id = pts.service_history_id
        JOIN PeerTrustData ptd ON pts.peer_trust_data_id = ptd.id
        WHERE ptd.peerID = ?;
        """
        service_history_rows = self.__execute_query(
            query_service_history, [peer_id]
        )

        service_history = [
            ServiceHistoryRecord(
                satisfaction=row[0], weight=row[1], timestamp=row[2]
            )
            for row in service_history_rows
        ]

        # Fetch RecommendationHistory for the peer
        query_recommendation_history = """
        SELECT rh.satisfaction, rh.weight, rh.recommend_time
        FROM RecommendationHistory rh
        JOIN PeerTrustRecommendationHistory ptr ON rh.id = ptr.recommendation_history_id
        JOIN PeerTrustData ptd ON ptr.peer_trust_data_id = ptd.id
        WHERE ptd.peerID = ?;
        """
        recommendation_history_rows = self.__execute_query(
            query_recommendation_history, [peer_id]
        )

        recommendation_history = [
            RecommendationHistoryRecord(
                satisfaction=row[0], weight=row[1], timestamp=row[2]
            )
            for row in recommendation_history_rows
        ]

        # Construct PeerInfo
        peer_info = PeerInfo(
            id=peerID, organisations=self.get_peer_organisations(peerID), ip=ip
        )  # Assuming organisation info is not fetched here.

        # Construct and return PeerTrustData object
        return PeerTrustData(
            info=peer_info,
            has_fixed_trust=bool(has_fixed_trust),
            service_trust=service_trust,
            reputation=reputation,
            recommendation_trust=recommendation_trust,
            competence_belief=competence_belief,
            integrity_belief=integrity_belief,
            initial_reputation_provided_by_count=initial_reputation_count,
            service_history=service_history,
            recommendation_history=recommendation_history,
        )

    def get_peers_by_organisations(
        self, organisation_ids: List[str]
    ) -> List[PeerInfo]:
        """
        Fetch PeerInfo records for peers that belong to at least one of the given organisations.
        Each peer will also have their associated organisations.

        :param organisation_ids: List of organisation IDs to filter peers by.
        :return: List of PeerInfo objects with associated organisation IDs.
        """
        placeholders = ",".join("?" for _ in organisation_ids)
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
            organisations = row[2].split(",") if row[2] else []
            peers.append(
                PeerInfo(id=peerID, organisations=organisations, ip=ip)
            )

        return peers

    def insert_organisation_if_not_exists(
        self, organisation_id: OrganisationId
    ) -> None:
        """
        Inserts an organisation into the Organisation table if it doesn't already exist.

        :param organisation_id: The organisation ID to insert.
        """
        query = (
            "INSERT OR IGNORE INTO Organisation (organisationID) VALUES (?)"
        )
        self.__execute_query(query, [organisation_id])

    def insert_peer_organisation_connection(
        self, peer_id: PeerId, organisation_id: OrganisationId
    ) -> None:
        """
        Inserts a connection between a peer and an organisation in the PeerOrganisation table.

        :param peer_id: The peer's ID.
        :param organisation_id: The organisation's ID.
        """
        self.__insert_peer_organisation(peer_id, organisation_id)

    def store_connected_peers_list(self, peers: List[PeerInfo]) -> None:
        """
        Stores a list of PeerInfo instances into the database.

        :param peers: A list of PeerInfo instances to be stored.
        """

        peer_ids = [
            peer.id for peer in peers
        ]  # Extract the peer IDs from list L
        placeholders = ",".join("?" for _ in peer_ids)
        delete_query = (
            f"DELETE FROM PeerInfo WHERE peerID NOT IN ({placeholders})"
        )
        self.__execute_query(delete_query, peer_ids)

        for peer_info in peers:
            peer = {
                "peerID": peer_info.id,
                "ip": peer_info.ip,
            }
            self.__insert_peer_info(peer)

            for organisation_id in peer_info.organisations:
                self.insert_organisation_if_not_exists(organisation_id)
                self.insert_peer_organisation_connection(
                    peer_info.id, organisation_id
                )

    def get_connected_peers(self) -> List[PeerInfo]:
        """
        Retrieves a list of PeerInfo instances from the database, including associated organisations.

        :return: A list of PeerInfo instances.
        """
        peer_info_list = []

        with SQLiteDB._lock:
            # Step 1: Query the PeerInfo table to get all peer information
            peer_info_query = "SELECT peerID, ip FROM PeerInfo"
            peer_info_results = self.__execute_query(peer_info_query)

            # Step 2: For each peer, get the associated organisations from PeerOrganisation table
            for row in peer_info_results:
                peer_id = row[0]  # peerID is the first column
                ip = row[1]  # ip is the second column

                # Step 3: Get associated organisations from PeerOrganisation table
                organisations = self.get_peer_organisations(peer_id)

                # Step 4: Create the PeerInfo object and add to the list
                peer_info = PeerInfo(
                    id=peer_id, organisations=organisations, ip=ip
                )
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

    def __insert_peer_info(self, peer_info: dict) -> None:
        """
        Inserts or updates the given PeerInfo object in the database.

        :param peer_info: The PeerInfo object to insert or update.
        """
        # Insert or replace PeerInfo
        self.__save("PeerInfo", peer_info)

    def __insert_peer_organisation(
        self, peer_id: PeerId, organisation_id: OrganisationId
    ) -> None:
        """
        Inserts a PeerOrganisation record.

        :param peer_id: The peer's ID.
        :param organisation_id: The organisation's ID.
        """
        query = """
        INSERT OR REPLACE INTO PeerOrganisation (peerID, organisationID)
        VALUES (?, ?);
        """
        self.__execute_query(query, [peer_id, organisation_id])

    def __connect(self) -> None:
        """
        Establishes a connection to the SQLite database.
        """
        self.__slips_log(f"Connecting to SQLite database at {self.db_path}")
        self.connection = sqlite3.connect(
            self.db_path, check_same_thread=False
        )

        if self.connection is None:
            self.__slips_log("Failed to connect to the SQLite database!")
            raise ConnectionError("SQLite connection failed")

    def __execute_query(
        self, query: str, params: Optional[List[Any]] = None
    ) -> List[Any]:
        """
        Executes a given SQL query and returns the results.

        :param query: The SQL query to execute.
        :param params: Optional list of parameters for parameterized queries.
        :return: List of results returned from the executed query.
        """
        with SQLiteDB._lock:
            self.__slips_log(f"Executing query: {query}")
            cursor = self.connection.cursor()

            # Split the query string by semicolons to handle multiple queries
            # queries = [q.strip() + ";" for q in query.split(";") if q.strip()]
            # results = []

            cursor = self.connection.cursor()
            # start_idx = 0
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
        columns = ", ".join(data.keys())
        placeholders = ", ".join("?" * len(data))
        query = f"INSERT OR REPLACE INTO {table} ({columns}) VALUES ({placeholders})"
        self.__slips_log(f"Saving data: {data} into table: {table}")
        self.__execute_query(query, list(data.values()))

    def __delete(
        self, table: str, condition: str, params: Optional[List[Any]] = None
    ) -> None:
        """
        Deletes rows from a table that match the condition.

        :param table: The table from which to delete the data.
        :param condition: A SQL condition for deleting rows (e.g., "id = ?").
        :param params: Optional list of parameters for parameterized queries.
        :return: None
        """
        query = f"DELETE FROM {table} WHERE {condition}"
        self.__slips_log(f"Deleting from table: {table} where {condition}")
        self.__execute_query(query, params)

    def close(self) -> None:
        """
        Closes the SQLite database connection.
        """
        if self.connection:
            self.__slips_log("Closing database connection")
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
            """,
            """
            CREATE TABLE IF NOT EXISTS PeerTrustData (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peerID TEXT,                  -- The peer providing the trust evaluation
                has_fixed_trust INTEGER NOT NULL CHECK (has_fixed_trust IN (0, 1)),   -- Whether the trust is dynamic or fixed
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
                target TEXT PRIMARY KEY,  -- The target of the intelligence (IP, domain, etc.)
                score REAL NOT NULL CHECK (score >= -1.0 AND score <= 1.0),
                confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
                confidentiality REAL -- Optional confidentiality level
            );
            """,
        ]

        for query in table_creation_queries:
            self.__slips_log(f"Creating tables with query: {query}")
            self.__execute_query(query)
