import configparser
import time
import modules.p2ptrust.testing.json_data as json_data
from modules.p2ptrust.utils.utils import save_ip_report_to_db
from modules.p2ptrust.p2ptrust import Trust
from modules.p2ptrust.trust.trustdb import TrustDB
from multiprocessing import Queue
from outputProcess import OutputProcess
import json

# TODO
# base_dir = "/home/dita/ownCloud/stratosphere/SLIPS/modules/p2ptrust/testing/"
# data_dir = base_dir + "data/experiments-" + str(time.time()) + "/"
# os.mkdir(data_dir)


def init_tests(pigeon_port=6669):
    config = get_default_config()
    output_process_queue = Queue()
    output_process_thread = OutputProcess(output_process_queue, 1, 1, config)
    output_process_thread.start()

    # Start the DB
    __database__.start()
    __database__.set_output_queue(output_process_queue)
    module_process = Trust(
        output_process_queue,
        config,
        data_dir,
        rename_with_port=False,
        pigeon_port=pigeon_port,
        rename_sql_db_file=False,
    )

    module_process.start()

    time.sleep(1)
    print("Initialization complete")

    return module_process


def set_ip_data(ip: str, data: dict):
    # TODO: remove the first call after database is fixed
    __database__.set_new_ip(ip)
    __database__.setInfoForIPs(ip, data)


def test_slips_integration():
    print("Add new peer on IP 192.168.0.4")
    # add a new peer abcsakughroiauqrghaui on IP 192.168.0.4
    __database__.publish(
        "p2p_gopy",
        '{"message_type":"peer_update","message_contents":{"peerid":"abcsakughroiauqrghaui","ip":"192.168.0.4","reliability":1,"timestamp":0}}',
    )
    time.sleep(0.5)
    print()

    print("Set evaluation for IP 192.168.0.4")
    # module_process.sqlite_db.insert_go_score("abcsakughroiauqrghaui", 1, 0)
    # module_process.sqlite_db.insert_go_ip_pairing("abcsakughroiauqrghaui", "192.168.0.4", 1) #B
    set_ip_data("192.168.0.4", {"score": -0.1, "confidence": 1})
    time.sleep(0.5)
    print()

    print("Add a new peer on IP 192.168.0.5")
    # add a new peer anotherreporterspeerid on IP 192.168.0.5
    __database__.publish(
        "p2p_gopy",
        '{"message_type":"peer_update","message_contents":{"peerid":"anotherreporterspeerid","ip":"192.168.0.5","timestamp":0}}',
    )
    time.sleep(0.5)
    print()
    __database__.publish(
        "p2p_gopy",
        '{"message_type":"peer_update","message_contents":{"peerid":"anotherreporterspeerid","reliability": 0.8,"timestamp":0}}',
    )
    time.sleep(0.5)
    print()

    print("Set evaluation for IP 192.168.0.5")
    # module_process.sqlite_db.insert_go_score("anotherreporterspeerid", 0.8, 0)
    # module_process.sqlite_db.insert_go_ip_pairing("anotherreporterspeerid", "192.168.0.5", 1) #C
    set_ip_data("192.168.0.5", {"score": 0.1, "confidence": 1})
    time.sleep(0.5)
    print()

    # network asks for data about 1.2.3.4
    print("Network asks about IP 1.2.3.4 (we know nothing about it)")
    data = json_data.ok_request
    __database__.publish(
        "p2p_gopy", '{"message_type":"go_data","message_contents":%s}' % data
    )
    time.sleep(0.5)
    print()

    # slips makes some detections
    print("Slips makes a detection of IP 1.2.3.4")
    set_ip_data("1.2.3.4", {"score": 0.3, "confidence": 1})
    time.sleep(0.5)
    print()

    print("Slips makes a detection of IP 1.2.3.6")
    set_ip_data("1.2.3.6", {"score": -1, "confidence": 0.7})
    time.sleep(0.5)
    time.sleep(1)
    print()

    print("Network shares detections about IP 1.2.3.40 and 1.2.3.5")
    # network shares some detections
    # {"key_type": "ip", "key": "1.2.3.40", "evaluation_type": "score_confidence", "evaluation": { "score": 0.9, "confidence": 0.6 }}
    # {"key_type": "ip", "key": "1.2.3.5", "evaluation_type": "score_confidence", "evaluation": { "score": 0.9, "confidence": 0.7 }}
    data = json_data.two_correctA
    published_data = '{"message_type":"go_data","message_contents":%s}' % data
    __database__.publish("p2p_gopy", published_data)
    data = json_data.two_correctB
    published_data = '{"message_type":"go_data","message_contents":%s}' % data
    __database__.publish("p2p_gopy", published_data)
    time.sleep(1)
    print()

    print("Network shares empty detection about IP 1.2.3.7")
    data = json_data.ok_empty_report
    __database__.publish(
        "p2p_gopy", '{"message_type":"go_data","message_contents":%s}' % data
    )
    time.sleep(1)
    print()

    print("Slips asks about data for 1.2.3.5")
    # slips asks for data about 1.2.3.5
    data_to_send = {
        "ip": "tst",
        "profileid": "profileid_192.168.1.1",
        "twid": "timewindow1",
        "proto": "TCP",
        "ip_state": "dstip",
        "stime": time.time(),
        "uid": "123",
        "cache_age": 1000,
    }
    data_to_send = json.dumps(data_to_send)
    __database__.publish("p2p_data_request", data_to_send)
    time.sleep(1)
    print()

    # network asks for data about 1.2.3.4
    print("Network asks about IP 1.2.3.4 (we know something now)")
    data = json_data.ok_request
    __database__.publish(
        "p2p_gopy", '{"message_type":"go_data","message_contents":%s}' % data
    )
    time.sleep(1)
    print()

    # shutdown
    __database__.publish("p2p_data_request", "stop_process")
    print()


def test_ip_info_changed():
    # TODO: wait until __database__.setInfoForIPs is fixed and then test if my module reacts correctly
    print(
        "Slips makes 5 repeating detections, but module is stupid and shares them all"
    )
    set_ip_data("1.2.3.6", {"score": 0.71, "confidence": 0.7})
    set_ip_data("1.2.3.6", {"score": 0.7, "confidence": 0.7})
    set_ip_data("1.2.3.6", {"score": 0.71, "confidence": 0.7})
    set_ip_data("1.2.3.6", {"score": 0.7, "confidence": 0.7})
    set_ip_data("1.2.3.6", {"score": 0.71, "confidence": 0.7})
    time.sleep(1)


def test_ip_data_save_to_redis():
    print("Data in slips for ip 1.2.3.4")
    print(__database__.get_ip_info("1.2.3.4"))

    print("Update data")
    save_ip_report_to_db("1.2.3.4", 1, 0.4, 0.4)

    print("Data in slips for ip 1.2.3.4")
    print(__database__.get_ip_info("1.2.3.4"))


def test_inputs():
    for test_case_name, test_case in json_data.__dict__.items():
        if test_case_name.startswith("_"):
            continue
        print()
        print("#########################")
        print("Running test case:", test_case_name)
        print("-------------------------")
        __database__.publish("p2p_gopy", f"go_data {test_case}")
        # the sleep is not needed, but it makes the log more readable
        time.sleep(1)

    print("Tests done.")


def get_default_config():
    cfg = configparser.ConfigParser()
    cfg.read_file(open("slips.yaml"))
    return cfg


def make_data():
    # the data is a list of reports from multiple peers. Each report contains information about the remote peer (his IP
    # and his credibility), and the data the peer sent. From slips, we know that the data sent contains the IP address
    # the peer is reporting (attacker), the score the peer assigned to that ip (how malicious does he find him) and the
    # confidence he has in his score evaluation.
    pass


def slips_listener_test():
    """
    A function to test if the retry queue is working as intended. Needs human interaction (disable network when asked)
    Test overview:
     - check ip A (will be cached successfully)
     - disable network
     - check ips B and C (they should be queued)
     - check ip from the same network as A (this should load from cache without errors, but not trigger retrying)
     - enable network
     - check ip from the same network as B (this will run and be cached, and trigger retrying. While retrying is in
         progress, it should check ip B and return cached result and then run a new query for C)
    :return: None
    """
    print("Running slips listener test")

    # invalid command
    __database__.publish("p2p_gopy", "foooooooooo")
    __database__.publish("p2p_gopy", "")

    # invalid command with parameters
    __database__.publish("p2p_gopy", "foooooooooo bar 3")

    # valid command, no parameters
    __database__.publish("p2p_gopy", "UPDATE")

    # valid update
    __database__.publish("p2p_gopy", "UPDATE ipaddress 1 1")
    __database__.publish("p2p_gopy", "UPDATE ipaddress 1.999999999999999 3")

    # update with unparsable parameters
    __database__.publish("p2p_gopy", "UPDATE ipaddress 1 five")
    __database__.publish("p2p_gopy", "UPDATE ipaddress 3")

    data = make_data()
    __database__.publish("p2p_gopy", f"GO_DATA {data}")

    # stop instruction
    __database__.publish("p2p_gopy", "stop_process")


def test_handle_slips_update():
    print("Slips asks about data for 1.2.3.5")
    # slips asks for data about 1.2.3.5 and cache age 1000
    data_to_send = {
        "ip": "tst",
        "profileid": "profileid_192.168.1.1",
        "twid": "timewindow1",
        "proto": "TCP",
        "ip_state": "dstip",
        "stime": time.time(),
        "uid": "123",
        "cache_age": 1000,
    }
    data_to_send = json.dumps(data_to_send)
    __database__.publish("p2p_data_request", data_to_send)

    time.sleep(1)


def test_evaluation_error():
    __database__.publish(
        "p2p_gopy", f"go_data {json_data.wrong_message_eval_structure}"
    )
    # __database__.publish("p2p_gopy", "go_data " + json_data.wrong_message_type)


def test_pigeon():
    # one pigeon is already running at port 6669, we start a second one on 6670
    init_tests(6670)

    # one of the peers makes a detection about IP 1.2.3.4
    # (both peers can read the same data from db, but only one is notified about it, so the other doesn't check it)
    __database__.r.hset(
        "IPsInfo", "1.2.3.4", '{"score":0.5, "confidence":0.8}'
    )
    __database__.publish("ip_info_change6669", "1.2.3.4")

    # peer 6669 should read the database, then notify the other peer.
    # The other peer should save the data in the reports table


def test_trustdb():
    trustdb = TrustDB(f"{data_dir}trustdb.db6660", None)
    print(trustdb.get_opinion_on_ip("1.1.1.3"))


if __name__ == "__main__":
    t = time.time()
    # test_trustdb()
    test_pigeon()

    # init_tests()

    # test_evaluation_error()

    # test_ip_info_changed()
    # test_inputs()
    # test_slips_integration()
    # test_ip_data_save_to_redis()
    # test_handle_slips_update()
    # test_pigeon()

    print(time.time() - t)
    time.sleep(10000000)
