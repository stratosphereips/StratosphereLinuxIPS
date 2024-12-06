def compute_discount_factor() -> float:
    """
    Computes discount factor used for `competence + (discount) * integrity` to lower
    the expectations of current peer for future interaction.

    :return: discount factor for integrity
    """
    # arbitrary value -1/2 explained in the paper
    return -0.5
