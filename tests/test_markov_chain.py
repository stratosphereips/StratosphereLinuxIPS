# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from tests.module_factory import ModuleFactory
from slips_files.common.markov_chains import (
    maximum_likelihood_probabilities,
    Matrix,
)
import math


@pytest.mark.parametrize(
    "init_vector",
    [
        # testcase1: basic two-state vector
        ({"A": 0.3, "B": 0.7}),
        # testcase2: three-state vector
        ({"X": 0.5, "Y": 0.2, "Z": 0.3}),
        # testcase3: empty vector
        ({}),
    ],
)
def test_set_init_vector(init_vector):
    matrix = ModuleFactory().create_markov_chain_obj()
    matrix.set_init_vector(init_vector)
    assert hasattr(matrix, "init_vector")
    assert matrix.init_vector == init_vector


@pytest.mark.parametrize(
    "init_vector",
    [
        # testcase1: basic two-state vector
        ({"A": 0.3, "B": 0.7}),
        # testcase2: three-state vector
        ({"X": 0.5, "Y": 0.2, "Z": 0.3}),
        # testcase3: empty vector
        ({}),
    ],
)
def test_get_init_vector(init_vector):
    matrix = ModuleFactory().create_markov_chain_obj()
    matrix.set_init_vector(init_vector)
    retrieved_vector = matrix.get_init_vector()
    assert retrieved_vector == init_vector


def test_get_init_vector_before_setting():
    matrix = ModuleFactory().create_markov_chain_obj()
    with pytest.raises(AttributeError):
        matrix.get_init_vector()


@pytest.mark.parametrize(
    "matrix_data, states, expected_prob",
    [
        # testcase1: simple chain
        (
            {("A", "B"): 0.7, ("B", "A"): 0.3},
            ["A", "B", "A"],
            math.log(0.7) + math.log(0.3),
        ),
        # testcase2: longer chain
        (
            {("X", "Y"): 0.5, ("Y", "Z"): 0.6, ("Z", "X"): 0.4},
            ["X", "Y", "Z", "X"],
            math.log(0.5) + math.log(0.6) + math.log(0.4),
        ),
        # testcase3: self-loop
        ({("A", "A"): 1.0}, ["A", "A", "A"], math.log(1.0) + math.log(1.0)),
        # testcase4: non-existent transition
        ({("A", "B"): 0.5}, ["C", "D"], float("-inf")),
        # testcase5: single state (no transition)
        ({}, ["A"], 0),
    ],
)
def test_walk_probability(matrix_data, states, expected_prob):
    matrix = ModuleFactory().create_markov_chain_obj()
    matrix.update(matrix_data)
    prob = matrix.walk_probability(states)
    assert math.isclose(prob, expected_prob)


@pytest.mark.parametrize(
    "states, order, " "expected_init_vector, " "expected_matrix",
    [
        # testcase1: cyclic-chain
        (
            ["X", "Y", "Z", "X", "Y", "Z"],
            1,
            {"X": 0.4, "Y": 0.4, "Z": 0.2},
            {("X", "Y"): 1.0, ("Y", "Z"): 1.0, ("Z", "X"): 1.0},
        ),
        # testcase2: self-loop
        (
            ["A", "A", "A", "A"],
            1,
            {"A": 1.0},
            {("A", "A"): 1.0},
        ),
        # testcase3: empty chain
        (
            [],
            1,
            {},
            {},
        ),
    ],
)
def test_maximum_likelihood_probabilities(
    states, order, expected_init_vector, expected_matrix
):
    init_vector, matrix = maximum_likelihood_probabilities(states, order)

    assert isinstance(matrix, Matrix)
    for key, value in expected_init_vector.items():
        assert key in init_vector
        assert math.isclose(init_vector[key], value, rel_tol=1e-9)
    for key, value in expected_matrix.items():
        assert key in matrix
        assert math.isclose(matrix[key], value, rel_tol=1e-9)

    assert len(matrix) == len(expected_matrix)
    matrix_init_vector = matrix.get_init_vector()
    for key, value in expected_init_vector.items():
        assert key in matrix_init_vector
        assert math.isclose(matrix_init_vector[key], value, rel_tol=1e-9)
