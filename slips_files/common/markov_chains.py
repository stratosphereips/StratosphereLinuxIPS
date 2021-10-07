# This file is from the Stratosphere Testing Framework
# See the file 'LICENSE' for copying permission.

# Library to compute some markov chain functions for the Stratosphere Project. We created them because pykov lacked the second order markov chains

import math
import sys

class Matrix(dict):
    """ The basic matrix object """
    def __init__(self, *args, **kw):
        super(Matrix,self).__init__(*args, **kw)
        self.itemlist = super(Matrix,self).keys()

    def set_init_vector(self, init_vector):
        self.init_vector = init_vector

    def get_init_vector(self):
        return self.init_vector

    def walk_probability(self, states):
        """
        Compute the probability of generating these states using ourselves.
        The returned value must be log.
        The main feature of this markov function is that is not trying to
        recognize each "state", it just uses each position of the vector
        given as new state. This allow us to have more comple states
        to work.
        """
        try:
            cum_prob = 0
            index = 0
            # index should be < that len - 1 because index starts in 0, and a two position vector has len 2, but the index of the last position is 1.
            # The len of the states should be > 1 because a state of only one char does NOT have any transition.
            while index < len(states) - 1 and len(states) > 1:
                statestuple = (states[index], states[index + 1])
                #print '\t\ttuple to search: {}'.format(statestuple)
                try:
                    prob12 = math.log(float(self[statestuple]))
                    #print '\t\tValue for this tuple: {}'.format(self[statestuple])
                    #print '\t\tprob12 inside {} (decimal {})'.format(prob12, math.exp(prob12))
                except KeyError:
                    # The transition is not in the matrix
                    #print '\t\twalk key error. The transition is not in the matrix'
                    #prob12 = float('-inf')
                    cum_prob = float('-inf')
                    break
                #except IndexError:
                    #print '\t\twalk index error'
                cum_prob += prob12
                #print '\t\ttotal prob so far {}'.format(cum_prob)
                index += 1
            #print '\t\tFinal Prob (log): {}'.format(cum_prob)
            return cum_prob
        except Exception as err:
            print( type(err))
            print( err.args)
            print( err)
            sys.exit(-1)


def maximum_likelihood_probabilities(states, order=1):
    """ Our own second order Markov Chain implementation """
    initial_matrix = {}
    initial_vector = {}
    total_transitions = 0
    amount_of_states = len(states)
    #print 'Receiving {} states to compute the Markov Matrix of {} order'.format(amount_of_states, order)
    # 1st order
    if order == 1:
        # Create matrix
        index = 0
        while index < amount_of_states:
            state1 = states[index]
            try:
                state2 = states[index + 1]
            except IndexError:
                # The last state is alone. There is no transaction, forget about it.
                break
            try:
                temp = initial_matrix[state1]
            except KeyError:
                # First time there is a transition FROM state1
                initial_matrix[state1] = {}
                initial_vector[state1] = 0
            try:
                value = initial_matrix[state1][state2]
                initial_matrix[state1][state2] = value + 1
            except KeyError:
                # First time there is a transition FROM state 1 to state2
                initial_matrix[state1][state2] = 1
            initial_vector[state1] += 1
            total_transitions += 1
            # Move along
            index += 1
        # Normalize using the initial vector
        matrix = Matrix()
        init_vector = {}
        for state1 in initial_matrix:
            # Create the init vector
            init_vector[state1] = initial_vector[state1] / float(total_transitions)
            for state2 in initial_matrix[state1]:
                value = initial_matrix[state1][state2]
                initial_matrix[state1][state2] = value / float(initial_vector[state1])
                # Change the style of the matrix
                matrix[(state1,state2)] = initial_matrix[state1][state2]
        matrix.set_init_vector(init_vector)
        #print init_vector
        #for value in matrix:
        #    print value, matrix[value]
    return (init_vector, matrix)
