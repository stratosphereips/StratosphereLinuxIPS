import pytest
from unittest.mock import MagicMock

from modules.fidesModule.model.peer import PeerInfo
from modules.fidesModule.model.peer_trust_data import PeerTrustData
from modules.fidesModule.model.threat_intelligence import (
    SlipsThreatIntelligence,
)
from modules.fidesModule.persistence.sqlite_db import SQLiteDB

from modules.fidesModule.model.recommendation_history import (
    RecommendationHistoryRecord,
)
from modules.fidesModule.model.service_history import ServiceHistoryRecord


@pytest.fixture
def db():
    # Create an in-memory SQLite database for testing
    logger = MagicMock()  # Mock the logger for testing purposes
    db_instance = SQLiteDB(logger, ":memory:")  # Using in-memory DB
    return db_instance


def test_db_connection_and_creation(db):
    # Check if connection is established
    assert db.connection is not None
    # Check if tables exist
    tables = db._SQLiteDB__execute_query(
        "SELECT name FROM sqlite_master WHERE type='table';"
    )
    assert len(tables) > 0  # Ensure tables are created


def test_store_slips_threat_intelligence(db):
    # Create a SlipsThreatIntelligence object
    intelligence = SlipsThreatIntelligence(
        target="example.com", score=-1, confidence=0.9, confidentiality=0.75
    )

    # Store the intelligence in the database
    db.store_slips_threat_intelligence(intelligence)

    # Fetch it back using the target
    result = db.get_slips_threat_intelligence_by_target("example.com")

    # Assert the retrieved data matches what was stored
    assert result is not None
    assert result.target == "example.com"
    assert result.score == -1
    assert result.confidence == 0.9
    assert result.confidentiality == 0.75


def test_get_slips_threat_intelligence_by_target(db):
    # Create a SlipsThreatIntelligence object and insert it
    intelligence = SlipsThreatIntelligence(
        target="192.168.1.1",
        score=0.70,
        confidence=1.0,
        confidentiality=None,  # Optional field left as None
    )
    db.store_slips_threat_intelligence(intelligence)

    # Retrieve the intelligence by the target (IP address)
    result = db.get_slips_threat_intelligence_by_target("192.168.1.1")

    # Assert the retrieved data matches what was stored
    assert result is not None
    assert result.target == "192.168.1.1"
    assert result.score == 0.7
    assert result.confidence == 1
    assert (
        result.confidentiality is None
    )  # Should be None since it was not set


def test_get_peer_trust_data(db):
    # Create peer info and peer trust data
    peer_info = PeerInfo(
        id="peer123", organisations=["org1", "org2"], ip="192.168.0.10"
    )
    peer_trust_data = PeerTrustData(
        info=peer_info,
        has_fixed_trust=True,
        service_trust=0.85,
        reputation=0.95,
        recommendation_trust=1,
        competence_belief=0.8,
        integrity_belief=0.0,
        initial_reputation_provided_by_count=10,
        service_history=[
            ServiceHistoryRecord(satisfaction=0.5, weight=0.9, timestamp=20.15)
        ],
        recommendation_history=[
            RecommendationHistoryRecord(
                satisfaction=0.8, weight=1.0, timestamp=1234.55
            )
        ],
    )

    # Store peer trust data in the database
    db.store_peer_trust_data(peer_trust_data)

    # Retrieve the stored peer trust data by peer ID
    result = db.get_peer_trust_data("peer123")

    # Assert the retrieved data matches what was stored
    assert result is not None
    assert result.info.id == "peer123"
    assert result.info.ip == "192.168.0.10"
    assert result.service_trust == 0.85
    assert result.reputation == 0.95
    assert result.recommendation_trust == 1
    assert result.competence_belief == 0.8
    assert result.integrity_belief == 0.0
    assert result.initial_reputation_provided_by_count == 10
    assert len(result.service_history) == 1
    assert result.service_history[0].satisfaction == 0.5
    assert len(result.recommendation_history) == 1
    assert result.recommendation_history[0].satisfaction == 0.8


def test_get_connected_peers_1(db):
    # Create PeerInfo data for multiple peers
    peers = [
        PeerInfo(id="peerA", organisations=["orgA"], ip="192.168.0.1"),
        PeerInfo(id="peerB", organisations=["orgB", "orgC"], ip="192.168.0.2"),
    ]

    # Store connected peers in the database
    db.store_connected_peers_list(peers)

    # Fetch all connected peers
    connected_peers = db.get_connected_peers()

    # Assert the connected peers were retrieved correctly
    assert len(connected_peers) == 2
    assert connected_peers[0].id == "peerA"
    assert connected_peers[1].id == "peerB"
    assert connected_peers[0].ip == "192.168.0.1"
    assert "orgB" in connected_peers[1].organisations


def test_get_peers_by_organisations(db):
    # Create and store PeerInfo data
    peers = [
        PeerInfo(id="peer1", organisations=["org1", "org2"], ip="10.0.0.1"),
        PeerInfo(id="peer2", organisations=["org2", "org3"], ip="10.0.0.2"),
        PeerInfo(id="peer3", organisations=["org3"], ip="10.0.0.3"),
    ]
    db.store_connected_peers_list(peers)

    # Query peers belonging to organisation "org2"
    result = db.get_peers_by_organisations(["org2"])

    # Assert the correct peers are returned
    assert len(result) == 2
    assert result[0].id == "peer1"
    assert result[1].id == "peer2"


def test_get_peers_by_minimal_recommendation_trust(db):
    # Insert peer trust data with varying recommendation trust
    peer1 = PeerTrustData(
        info=PeerInfo(id="peer1", organisations=["org1"], ip="10.0.0.1"),
        has_fixed_trust=True,
        service_trust=0.70,
        reputation=0.80,
        recommendation_trust=0.50,
        competence_belief=0.60,
        integrity_belief=0.70,
        initial_reputation_provided_by_count=3,
        service_history=[],  # Assuming an empty list for simplicity
        recommendation_history=[],  # Assuming an empty list for simplicity
    )

    peer2 = PeerTrustData(
        info=PeerInfo(id="peer2", organisations=["org2"], ip="10.0.0.2"),
        has_fixed_trust=False,
        service_trust=0.85,
        reputation=0.90,
        recommendation_trust=0.90,
        competence_belief=0.75,
        integrity_belief=0.80,
        initial_reputation_provided_by_count=5,
        service_history=[],
        recommendation_history=[],
    )

    # Store the peer trust data
    db.store_peer_trust_data(peer1)
    db.store_peer_trust_data(peer2)

    # Query peers with recommendation trust >= 70
    peers = db.get_peers_by_minimal_recommendation_trust(0.70)

    # Assert that only the appropriate peer is returned
    assert len(peers) == 1
    assert peers[0].id == "peer2"


def test_get_nonexistent_peer_trust_data(db):
    # Attempt to retrieve peer trust data for a non-existent peer
    result = db.get_peer_trust_data("nonexistent_peer")
    assert result is None


def test_insert_organisation_if_not_exists(db):
    # Organisation ID to be inserted
    organisation_id = "org123"

    # Insert organisation if it doesn't exist
    db.insert_organisation_if_not_exists(organisation_id)

    # Query the Organisation table to check if the organisation was inserted
    result = db._SQLiteDB__execute_query(
        "SELECT organisationID FROM Organisation WHERE organisationID = ?",
        [organisation_id],
    )

    # Assert that the organisation was inserted
    assert len(result) == 1
    assert result[0][0] == organisation_id


def test_insert_peer_organisation_connection(db):
    # Peer and Organisation IDs to be inserted
    peer_id = "peer123"
    organisation_id = "org123"

    # Insert the connection
    db.insert_peer_organisation_connection(peer_id, organisation_id)

    # Query the PeerOrganisation table to verify the connection
    result = db._SQLiteDB__execute_query(
        "SELECT peerID, organisationID FROM PeerOrganisation WHERE peerID = ? AND organisationID = ?",
        [peer_id, organisation_id],
    )

    # Assert the connection was inserted
    assert len(result) == 1
    assert result[0] == (peer_id, organisation_id)


def test_store_connected_peers_list(db):
    # Create PeerInfo objects to insert
    peers = [
        PeerInfo(id="peer1", organisations=["org1", "org2"], ip="192.168.1.1"),
        PeerInfo(id="peer2", organisations=["org3"], ip="192.168.1.2"),
    ]

    # Store the connected peers
    db.store_connected_peers_list(peers)

    # Verify the PeerInfo table
    peer_results = db._SQLiteDB__execute_query(
        "SELECT peerID, ip FROM PeerInfo"
    )
    assert len(peer_results) == 2
    assert peer_results[0] == ("peer1", "192.168.1.1")
    assert peer_results[1] == ("peer2", "192.168.1.2")

    # Verify the PeerOrganisation table
    org_results_peer1 = db._SQLiteDB__execute_query(
        "SELECT organisationID FROM PeerOrganisation WHERE peerID = ?",
        ["peer1"],
    )
    assert (
        len(org_results_peer1) == 2
    )  # peer1 should be connected to 2 organisations
    assert org_results_peer1[0][0] == "org1"
    assert org_results_peer1[1][0] == "org2"

    org_results_peer2 = db._SQLiteDB__execute_query(
        "SELECT organisationID FROM PeerOrganisation WHERE peerID = ?",
        ["peer2"],
    )
    assert (
        len(org_results_peer2) == 1
    )  # peer2 should be connected to 1 organisation
    assert org_results_peer2[0][0] == "org3"


def test_get_connected_peers_2(db):
    # Manually insert peer data into PeerInfo table
    db._SQLiteDB__execute_query(
        "INSERT INTO PeerInfo (peerID, ip) VALUES (?, ?)",
        ["peer1", "192.168.1.1"],
    )
    db._SQLiteDB__execute_query(
        "INSERT INTO PeerInfo (peerID, ip) VALUES (?, ?)",
        ["peer2", "192.168.1.2"],
    )

    # Manually insert associated organisations into PeerOrganisation table
    db._SQLiteDB__execute_query(
        "INSERT INTO PeerOrganisation (peerID, organisationID) VALUES (?, ?)",
        ["peer1", "org1"],
    )
    db._SQLiteDB__execute_query(
        "INSERT INTO PeerOrganisation (peerID, organisationID) VALUES (?, ?)",
        ["peer1", "org2"],
    )
    db._SQLiteDB__execute_query(
        "INSERT INTO PeerOrganisation (peerID, organisationID) VALUES (?, ?)",
        ["peer2", "org3"],
    )

    # Call the function to retrieve connected peers
    connected_peers = db.get_connected_peers()

    # Verify the connected peers list
    assert len(connected_peers) == 2
    assert connected_peers[0].id == "peer1"
    assert connected_peers[0].ip == "192.168.1.1"
    assert connected_peers[0].organisations == ["org1", "org2"]
    assert connected_peers[1].id == "peer2"
    assert connected_peers[1].ip == "192.168.1.2"
    assert connected_peers[1].organisations == ["org3"]


def test_get_peer_organisations(db):
    # Insert a peer and associated organisations into PeerOrganisation
    peer_id = "peer123"
    organisations = ["org1", "org2", "org3"]
    for org_id in organisations:
        db._SQLiteDB__execute_query(
            "INSERT INTO PeerOrganisation (peerID, organisationID) VALUES (?, ?)",
            [peer_id, org_id],
        )

    # Retrieve organisations for the peer
    result = db.get_peer_organisations(peer_id)

    # Assert that the retrieved organisations match what was inserted
    assert set(result) == set(
        organisations
    )  # Ensure all organisations are returned, order does not matter
