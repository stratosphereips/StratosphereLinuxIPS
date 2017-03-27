import unittest
from mock import patch
from datetime import timedelta
from slips import Tuple, Processor
from multiprocessing import Queue


class TestTuple(unittest.TestCase):
    def setUp(self):
        # Using Github as dst ip
        self.tuple = Tuple("127.0.0.1-192.30.253.112-8080-TCP")
        self.tuple.verbose = 0
        self.tuple.set_debug(0)

    def test_compute_periodicity(self):
        self.tuple.compute_periodicity()
        self.assertEqual(self.tuple.periodicity, -1)

        self.tuple.T1 = timedelta(seconds=7200)
        self.tuple.T2 = timedelta(seconds=8000)
        self.tuple.compute_periodicity()
        self.assertEqual(self.tuple.state, "00")
        self.assertAlmostEqual(self.tuple.TD, 1.11, places=2)
        self.assertEqual(self.tuple.periodic, 2)

    def test_compute_duration(self):
        self.tuple.current_duration = 0.0
        self.tuple.compute_duration()
        self.assertEqual(self.tuple.duration, 1)

        self.tuple.current_duration = 5
        self.tuple.compute_duration()
        self.assertEqual(self.tuple.duration, 2)

        self.tuple.current_duration = 5
        self.tuple.compute_duration()
        self.assertEqual(self.tuple.duration, 2)

        self.tuple.current_duration = 15
        self.tuple.compute_duration()
        self.assertEqual(self.tuple.duration, 3)

    def test_compute_size(self):
        self.tuple.compute_size()
        self.assertEqual(self.tuple.size, 1)

        self.tuple.current_size = 500
        self.tuple.compute_size()
        self.assertEqual(self.tuple.size, 2)

        self.tuple.current_size = 1500
        self.tuple.compute_size()
        self.assertEqual(self.tuple.size, 3)

    def test_compute_state(self):
        self.tuple.periodic = -1
        self.tuple.size = 1
        self.tuple.duration = 2
        self.tuple.compute_state()
        self.assertEqual(self.tuple.state, "2")

        self.tuple.compute_state()
        self.assertEqual(self.tuple.state, "22")

        self.tuple.periodic = 1
        self.tuple.size = 2
        self.tuple.duration = 3
        self.tuple.compute_state()
        self.assertEqual(self.tuple.state, "22f")

        self.tuple.periodic = 4
        self.tuple.size = 3
        self.tuple.duration = 1
        self.tuple.compute_state()
        self.assertEqual(self.tuple.state, "22fX")

        # The code silently ignores higher values
        self.tuple.periodic = 8
        self.tuple.compute_state()
        self.assertEqual(self.tuple.state, "22fX")

    def test_compute_symbols(self):
        self.tuple.T2 = timedelta(seconds=350)
        self.tuple.compute_symbols()
        self.assertEqual(self.tuple.state, "*")

        # Add another one
        self.tuple.T2 = timedelta(seconds=3)
        self.tuple.compute_symbols()
        self.assertEqual(self.tuple.state, "*.")

        # Add a third one
        self.tuple.T2 = timedelta(seconds=250)
        self.tuple.compute_symbols()
        self.assertEqual(self.tuple.state, "*.+")

        # Add the final one to test all branches
        self.tuple.T2 = timedelta(seconds=50)
        self.tuple.compute_symbols()
        self.assertEqual(self.tuple.state, "*.+,")

    def test_add_new_flow(self):
        column_values = ['2017/02/23 19:20:0.123', 2, 'TCP', '127.0.0.1', 12345, 'dir',
                         '193.212.4.21', 443, 1, 'stos', 'dtos', 2, 3800]

        self.tuple.add_new_flow(column_values)
        self.assertEqual(self.tuple.current_duration, 2.)
        self.assertEqual(self.tuple.proto, 'TCP')
        self.assertEqual(self.tuple.amount_of_flows, 1)
        self.assertEqual(self.tuple.state, '8')

        # Add another one
        column_values2 = ['2017/02/23 19:22:0.123', 1, 'TCP', '127.0.0.1', 12345, 'dir',
                          '193.212.4.48', 443, 1, 'stos', 'dtos', 2, 7800]
        self.tuple.add_new_flow(column_values2)
        self.assertEqual(self.tuple.amount_of_flows, 2)
        self.assertEqual(self.tuple.current_duration, 1.)
        self.assertEqual(self.tuple.state, '88+')


class TestProcessor(unittest.TestCase):

    def setUp(self):
        queue = Queue()
        self.p = Processor(queue, timedelta(minutes=120), False, False, -1, False, 0.002, 0, [], 1)
        # queue, slot_width, get_whois, verbose, amount, dontdetect, threshold, debug, whitelist)
        self.assertEqual(self.p.dontdetect, False)
        self.assertEqual(self.p.get_whois, False)
        self.assertEqual(len(self.p.tuples.keys()), 0)

    def test_get_tuple(self):
        self.p.get_tuple("127.0.0.1-192.30.253.112-8080-TCP")
        self.assertEqual(len(self.p.tuples.keys()), 1)

        # Add a second Tuple
        self.p.get_tuple("127.0.0.1-192.30.253.112-443-TCP")
        self.assertEqual(len(self.p.tuples.keys()), 2)

        # Add the first Tuple again
        self.p.get_tuple("127.0.0.1-192.30.253.112-8080-TCP")
        self.assertEqual(len(self.p.tuples.keys()), 2)

    @patch('modules.markov_models_1.__markov_models__.detect')
    def test_process_out_of_time_slot(self, mock_api_call):
        mock_api_call.return_value = (True, True, True)

        column_values = ['2017/02/23 19:20:0.123', 2, 'TCP', '127.0.0.1', 12345, 'dir',
                         '193.212.4.21', '443', '1', 'stos', 'dtos', '2', 3800]

        # Add two tuples in the list
        self.p.get_tuple("127.0.0.1-192.30.253.112-8080-TCP")
        self.p.get_tuple("127.0.0.1-192.30.253.112-443-TCP")
        self.assertIn("127.0.0.1-192.30.253.112-8080-TCP", self.p.tuples.keys())
        self.assertIn("127.0.0.1-192.30.253.112-443-TCP", self.p.tuples.keys())
        self.assertEqual(len(self.p.tuples.keys()), 2)

        # Increase the amount of flows for this Tuple
        t = self.p.tuples['127.0.0.1-192.30.253.112-443-TCP']

        # Try to add a new Tuple with last_tw True
        self.p.process_out_of_time_slot(column_values, last_tw=True)
        self.assertEqual(len(self.p.tuples.keys()), 2)
        self.assertIn("127.0.0.1-192.30.253.112-8080-TCP", self.p.tuples.keys())
        self.assertIn("127.0.0.1-192.30.253.112-443-TCP", self.p.tuples.keys())
        self.assertNotIn("127.0.0.1-193.212.4.21-443-TCP", self.p.tuples.keys())

        # Try to add a new Tuple with last_tw True
        self.p.process_out_of_time_slot(column_values, last_tw=False)
        self.assertEqual(len(self.p.tuples.keys()), 3)
        self.assertIn("127.0.0.1-192.30.253.112-8080-TCP", self.p.tuples.keys())
        self.assertIn("127.0.0.1-193.212.4.21-443-TCP", self.p.tuples.keys())
        self.assertIn("127.0.0.1-192.30.253.112-443-TCP", self.p.tuples.keys())

    @patch('modules.markov_models_1.__markov_models__.detect')
    def test_detect(self, mock_api_call):
        # Here we need a mock of the model detection

        mock_api_call.return_value = (True, True, True)
        t = self.p.get_tuple("127.0.0.1-192.30.253.112-8080-TCP")

        self.p.detect(t)
        self.assertEqual(t.get_detected_label(), True)

    @patch('modules.markov_models_1.__markov_models__.detect')
    def test_run(self, mock_api_call):
        mock_api_call.return_value = (True, True, True)

        # If the amount is equal or less than the tuple states do not try to detect
        self.p.amount = 2

        self.p.queue.put("2017/02/24 12:00:0.123,2,TCP,127.0.0.1,12345,dir,193.212.4.21,443,1,stos,dtos,2,3800")
        self.p.queue.put("stop")

        self.p.run()
        self.assertEqual(len(self.p.tuples.keys()), 1)
        self.assertIn("127.0.0.1-193.212.4.21-443-TCP", self.p.tuples.keys())

        # Retrieve the tuple
        t = self.p.tuples['127.0.0.1-193.212.4.21-443-TCP']
        self.assertEqual(t.state, "8")

        self.assertEqual(t.get_detected_label(), False)
