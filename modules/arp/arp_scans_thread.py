import asyncio

from slips_files.common.abstracts.ithread import IThread


class ARPScansProcessor(IThread):
    """
    Thread that waits for X seconds to see if more ARP scan evidence
    arrives for the same profile and twid to combine them into 1 single
    evidence
    """

    async def init(self):
        # wait 10s for mmore arp scan evidence to come
        self.time_to_wait = 10

    async def start(self):
        # this evidence is the one that triggered this thread
        scans_ctr = 0
        while not self.should_stop():
            try:
                evidence: dict = await asyncio.wait_for(
                    self.pending_arp_scan_evidence.get(), timeout=0.5
                )
            except asyncio.TimeoutError:
                # nothing in queue
                await asyncio.sleep(5)
                continue
            # unpack the evidence that triggered the task
            (ts, profileid, twid, uids) = evidence

            # wait 10s if a new evidence arrived
            await asyncio.sleep(self.time_to_wait)

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

            self.set_evidence_arp_scan(ts, profileid, twid, uids)
