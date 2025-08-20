import asyncio
import queue

from modules.arp.set_evidence import ARPSetEvidenceHelper
from slips_files.common.abstracts.ithread import IThread


class ARPScansProcessor(IThread):
    """
    Thread that waits for X seconds to see if more ARP scan evidence
    arrives for the same profile and twid to combine them into 1 single
    evidence
    """

    async def init(self, **kwargs):
        # wait 10s for mmore arp scan evidence to come
        self.time_to_wait = 10
        self.set_evidence = ARPSetEvidenceHelper(self.db, self.conf, self.args)
        self.pending_arp_scan_evidence: queue.Queue = kwargs.get(
            "pending_arp_scan_evidence"
        )

    async def start(self):
        scans_ctr = 0
        while not self.should_stop():
            try:
                evidence: dict = self.get_msg_from_q(
                    self.pending_arp_scan_evidence.get(), timeout=0.5
                )
            except Exception:
                continue
            print(f"@@@@@@@@@@@@@@@@ evidence {evidence}")
            # unpack the evidence that triggered the task
            (ts, profileid, twid, uids) = evidence

            # wait 10s if a new evidence arrived
            await asyncio.sleep(self.time_to_wait)
            # now keep getting evidence from the queue and combine all
            # similar ones, and put back in the queue all the ones that
            # wont be combined.
            while True:
                try:
                    new_evidence = self.pending_arp_scan_evidence.get(
                        timeout=0.5
                    )
                except Exception:
                    # queue is empty
                    break

                (ts2, profileid2, twid2, uids2) = new_evidence
                if profileid == profileid2 and twid == twid2:
                    # this should be combined with the past alert
                    ts = ts2
                    uids += uids2
                else:
                    # this is an ip performing arp scan in a diff
                    # profile or a diff twid, we shouldn't accumulate its
                    # evidence  store it back in the queue until we're done
                    # with the current one
                    scans_ctr += 1
                    self.pending_arp_scan_evidence.put(new_evidence)
                    if scans_ctr == 3:
                        scans_ctr = 0
                        break

            # done combining similar ones, now that the queue is empty, set
            # the evidence
            self.set_evidence.arp_scan(ts, profileid, twid, uids)
            # after we set evidence, clear the dict so we can detect if it
            # does another scan
            try:
                self.cache_arp_requests.pop(f"{profileid}_{twid}")
            except KeyError:
                # when a tw is closed, we clear all its' entries from the
                # cache_arp_requests dict
                # having keyerr is a result of closing a timewindow before
                # setting an evidence
                # ignore it
                pass
