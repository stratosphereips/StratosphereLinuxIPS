import sqlite3

# Connect to the SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('testing_database.db')
cursor = conn.cursor()

# List of SQL table creation queries
table_creation_queries = [
    """
    CREATE TABLE IF NOT EXISTS PeerInfo (
        peerID TEXT PRIMARY KEY,
        ip VARCHAR(39)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ServiceHistory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peerID TEXT,
        satisfaction FLOAT NOT NULL CHECK (satisfaction >= 0.0 AND satisfaction <= 1.0),
        weight FLOAT NOT NULL CHECK (weight >= 0.0 AND weight <= 1.0),
        service_time FLOAT NOT NULL,
        FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS RecommendationHistory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peerID TEXT,
        satisfaction FLOAT NOT NULL CHECK (satisfaction >= 0.0 AND satisfaction <= 1.0),
        weight FLOAT NOT NULL CHECK (weight >= 0.0 AND weight <= 1.0),
        recommend_time FLOAT NOT NULL,
        FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS Organisation (
        organisationID TEXT PRIMARY KEY
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
        peerID TEXT,
        has_fixed_trust INTEGER NOT NULL CHECK (has_fixed_trust IN (0, 1)),
        service_trust REAL NOT NULL CHECK (service_trust >= 0.0 AND service_trust <= 1.0),
        reputation REAL NOT NULL CHECK (reputation >= 0.0 AND reputation <= 1.0),
        recommendation_trust REAL NOT NULL CHECK (recommendation_trust >= 0.0 AND recommendation_trust <= 1.0),
        competence_belief REAL NOT NULL CHECK (competence_belief >= 0.0 AND competence_belief <= 1.0),
        integrity_belief REAL NOT NULL CHECK (integrity_belief >= 0.0 AND integrity_belief <= 1.0),
        initial_reputation_provided_by_count INTEGER NOT NULL,
        FOREIGN KEY (peerID) REFERENCES PeerInfo(peerID) ON DELETE CASCADE
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

# Sample data to insert into tables
sample_data = {
    "PeerInfo": [
        ("peer1", "192.168.1.1"),
        ("peer2", "192.168.1.2"),
        ("peer3", "192.168.1.3")
    ],
    "ServiceHistory": [
        ("peer1", 0.8, 0.9, 1.5),
        ("peer2", 0.6, 0.7, 2.0),
        ("peer3", 0.9, 0.95, 0.5)
    ],
    "RecommendationHistory": [
        ("peer1", 0.85, 0.9, 1.2),
        ("peer2", 0.75, 0.8, 1.0),
        ("peer3", 0.95, 0.99, 0.8)
    ],
    "Organisation": [
        ("org1"),
        ("org2"),
        ("org3")
    ],
    "PeerOrganisation": [
        ("peer1", "org1"),
        ("peer1", "org2"),
        ("peer2", "org2"),
        ("peer3", "org3")
    ],
    "PeerTrustData": [
        ("peer1", 1, 0.8, 0.9, 0.85, 0.9, 0.95, 0.8, 3),
        ("peer2", 0, 0.7, 0.75, 0.7, 0.8, 0.85, 0.7, 2),
        ("peer3", 1, 0.9, 0.95, 0.9, 1.0, 0.95, 0.9, 5)
    ],
    "ThreatIntelligence": [
        ("peer1", 0.8, 0.9, "target1", 0.7),
        ("peer2", 0.6, 0.7, "target2", 0.5),
        ("peer3", 0.9, 0.95, "target3", 0.85)
    ]
}

# Execute the table creation queries
for query in table_creation_queries:
    cursor.execute(query)

# Insert sample data into tables
for table, data in sample_data.items():
    if table == "PeerInfo":
        cursor.executemany("INSERT INTO PeerInfo (peerID, ip) VALUES (?, ?)", data)
    elif table == "ServiceHistory":
        cursor.executemany("INSERT INTO ServiceHistory (peerID, satisfaction, weight, service_time) VALUES (?, ?, ?, ?)", data)
    elif table == "RecommendationHistory":
        cursor.executemany("INSERT INTO RecommendationHistory (peerID, satisfaction, weight, recommend_time) VALUES (?, ?, ?, ?)", data)
    elif table == "Organisation":
        cursor.executemany("INSERT INTO Organisation (organisationID) VALUES (?)", data)
    elif table == "PeerOrganisation":
        cursor.executemany("INSERT INTO PeerOrganisation (peerID, organisationID) VALUES (?, ?)", data)
    elif table == "PeerTrustData":
        cursor.executemany("INSERT INTO PeerTrustData (peerID, has_fixed_trust, service_trust, reputation, recommendation_trust, competence_belief, integrity_belief, initial_reputation_provided_by_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", data)
    elif table == "ThreatIntelligence":
        cursor.executemany("INSERT INTO ThreatIntelligence (peerID, score, confidence, target, confidentiality) VALUES (?, ?, ?, ?, ?)", data)

# Commit the changes and close the connection
conn.commit()
conn.close()

print("Testing database created and populated successfully!")
