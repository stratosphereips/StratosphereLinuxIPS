from typing import Optional
import sys
import traceback


def check_suricata_states(state) -> Optional[str]:
    """
    There are different states in which a flow can be.
    Suricata distinguishes three flow-states for TCP and two for
     UDP. For TCP,
    these are: New, Established and Closed,for UDP only new and
    established.
    For each of these states Suricata can employ different timeouts.
    """
    if "new" in state or "established" in state:
        return "Established"
    elif "closed" in state:
        return "Not Established"


def check_zeek_states(state) -> Optional[str]:
    # We have varius type of states depending on the type of flow.
    # For Zeek
    if state in ("S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"):
        return "Not Established"
    elif state in ("S1", "SF", "S2", "S3", "RSTO", "RSTP", "OTH"):
        return "Established"


def check_argus_states(state) -> Optional[str]:
    pre = state.split("_")[0]
    suf = state.split("_")[1]
    if "S" in pre and "A" in pre and "S" in suf and "A" in suf:
        """
        Examples:
        SA_SA
        SR_SA
        FSRA_SA
        SPA_SPA
        SRA_SPA
        FSA_FSA
        FSA_FSPA
        SAEC_SPA
        SRPA_SPA
        FSPA_SPA
        FSRPA_SPA
        FSPA_FSPA
        FSRA_FSPA
        SRAEC_SPA
        FSPA_FSRPA
        FSAEC_FSPA
        FSRPA_FSPA
        SRPAEC_SPA
        FSPAEC_FSPA
        SRPAEC_FSRPA
        """
        return "Established"
    elif "PA" in pre and "PA" in suf:
        # Tipical flow that was reported in the middle
        """
        Examples:
        PA_PA
        FPA_FPA
        """
        return "Established"
    elif "ECO" in pre:
        return "ICMP Echo"
    elif "ECR" in pre:
        return "ICMP Reply"
    elif "URH" in pre:
        return "ICMP Host Unreachable"
    elif "URP" in pre:
        return "ICMP Port Unreachable"
    else:
        """
        Examples:
        S_RA
        S_R
        A_R
        S_SA
        SR_SA
        FA_FA
        SR_RA
        SEC_RA
        """
        return "Not Established"


def check_tcp_states(state, pkts) -> Optional[str]:
    pre = state.split("_")[0]
    if "EST" in pre:
        # TCP
        return "Established"
    elif "RST" in pre:
        # TCP. When -z B is not used in argus, states are single words.
        # Most connections are reseted when finished and therefore are
        # established
        # It can happen that is reseted being not established, but we
        # can't tell without -z b.
        # So we use as heuristic the amount of packets. If <=3, then is
        # not established because the OS retries 3 times.
        return "Not Established" if int(pkts) <= 3 else "Established"
    elif "FIN" in pre:
        # TCP. When -z B is not used in argus, states are single words.
        # Most connections are finished with FIN when finished and
        # therefore are established
        # It can happen that is finished being not established, but we
        # can't tell without -z b.
        # So we use as heuristic the amount of packets. If <=3, then is
        # not established because the OS retries 3 times.
        return "Not Established" if int(pkts) <= 3 else "Established"
    else:
        """
        Examples:
        S_
        FA_
        PA_
        FSA_
        SEC_
        SRPA_
        """
        return "Not Established"


def check_udp_states(state) -> Optional[str]:
    pre = state.split("_")[0]
    if "CON" in pre:
        # UDP
        return "Established"
    elif "INT" in pre:
        # UDP trying to connect, NOT preciselly not established but also
        # NOT 'Established'. So we considered not established because there
        # is no confirmation of what happened.
        return "Not Established"


def check_icmp_states(state) -> Optional[str]:
    pre = state.split("_")[0]
    if "ECO" in pre:
        # ICMP
        return "Established"
    elif "UNK" in pre:
        # ICMP6 unknown upper layer
        return "Established"


def get_final_state_from_flags(self, state, pkts) -> str:
    """
    Analyze the flags given and return a summary of the state.
    Should work with Argus and Bro flags
    We receive the pakets to distinguish some Reset connections
    """
    try:
        if state := check_suricata_states(state):
            return state
        if state := check_zeek_states(state):
            return state
        if state := check_argus_states(state):
            return state
    except IndexError:
        # suf does not exist, which means that this is some ICMP or
        # no response was sent for UDP or TCP
        if state := check_icmp_states(state):
            return state
        if state := check_udp_states(state):
            return state
        if state := check_tcp_states(state, pkts):
            return state

        return "Not Established"

    except Exception:
        exception_line = sys.exc_info()[2].tb_lineno
        self.print(
            f"Error in get_final_state_from_flags() " f"line {exception_line}",
            0,
            1,
        )
        self.print(traceback.format_exc(), 0, 1)
