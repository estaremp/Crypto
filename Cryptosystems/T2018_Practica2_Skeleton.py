#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES

MODE_CIPHER = 0
MODE_DECIPHER = 1

# --- IMPLEMENTATION GOES HERE ---------------------------------------------
#  Student helpers (functions, constants, etc.) can be defined here, if needed

from functools import reduce

# --------------------------------------------------------------------------


def uoc_lfsr_sequence(polynomial, initial_state, output_bits):
    """
    Returns the output sequence of output_bits bits of an LFSR with a given initial state and connection polynomial.

    :param polynomial: list of integers, with the coefficients of the connection polynomial that define the LFSR.
    :param initial_state: list of integers with the initial state of the LFSR
    :param output_bits: integer, number of bits of the output sequence
    :return: a list of output_bits bits
    """
    result = None

    # --- IMPLEMENTATION GOES HERE ---

    gates = len(initial_state)
    state = initial_state
    seq = []
    i = 0

    while (i<output_bits):
        state.insert(gates,reduce(lambda a,b: a^b,[aa*bb for aa,bb in zip(state,polynomial)]))
        seq.append(state.pop(0))
        i += 1

    result = seq
    # --------------------------------

    return result


def uoc_ext_a5_pseudo_random_gen(params_pol_0, params_pol_1, params_pol_2, clocking_bits, output_bits):
    """
    Implements extended A5's pseudorandom generator.
    :param params_pol_0: two-element list describing the first LFSR: the first element contains a list with the
    coefficients of the connection polynomial, the second element contains a list with the initial state of the LFSR.
    :param params_pol_1: two-element list describing the second LFSR: the first element contains a list with the
    coefficients of the connection polynomial, the second element contains a list with the initial state of the LFSR.
    :param params_pol_2: two-element list describing the third LFSR: the first element contains a list with the
    coefficients of the connection polynomial, the second element contains a list with the initial state of the LFSR.
    :param clocking_bits: three-element list, with the clocking bits of each LFSR
    :param output_bits: integer, number of bits of the output sequence
    :return: list of output_bits elements with the pseudo random sequence
    """

    sequence = []

    # --- IMPLEMENTATION GOES HERE ---

    state_1 = params_pol_0[1]
    state_2 = params_pol_1[1]
    state_3 = params_pol_2[1]
    
    gates_1 = len(state_1)
    gates_2 = len(state_2)
    gates_3 = len(state_3)
    
    conn_1 = params_pol_0[0]
    conn_2 = params_pol_1[0]
    conn_3 = params_pol_2[0]
    
    if (clocking_bits[0]>=gates_1) or (clocking_bits[1]>=gates_2) or (clocking_bits[2]>=gates_3):
        print("ERROR: Clocking bits are not valid for this set up.")
    
    i = 0
    while (i<output_bits):
        
        z = state_1[0]^state_2[0]^state_3[0]
        sequence.append(z)
        
        #check state of clocking bits
        clck = [state_1[-clocking_bits[0]-1],state_2[-clocking_bits[1]-1],state_3[-clocking_bits[2]-1]]
        vote = max(set(clck), key = clck.count)

        if clck[0]==vote:
            state_1.insert(gates_1,reduce(lambda a,b: a^b,[aa*bb for aa,bb in zip(state_1,conn_1)]))
            state_1.pop(0)
        if clck[1]==vote:
            state_2.insert(gates_2,reduce(lambda a,b: a^b,[aa*bb for aa,bb in zip(state_2,conn_2)]))
            state_2.pop(0)
        if clck[2]==vote:
            state_3.insert(gates_3,reduce(lambda a,b: a^b,[aa*bb for aa,bb in zip(state_3,conn_3)]))
            state_3.pop(0)
        
        i += 1
                
    # --------------------------------

    return sequence


def uoc_a5_cipher(initial_state_0, initial_state_1, initial_state_2, message, mode):
    """
    Implements ciphering/deciphering with the A5 pseudo random generator.

    :param initial_state_0: list, initial state of the first LFSR
    :param initial_state_1: list, initial state of the second LFSR
    :param initial_state_2: list, initial state of the third LFSR
    :param message: string, plaintext to cipher (mode=MODE_CIPHER) or ciphertext to decipher (mode=MODE_DECIPHER)
    :param mode: MODE_CIPHER or MODE_DECIPHER, whether to cipher or decipher
    :return: string, ciphertext (mode=MODE_CIPHER) or plaintext (mode=MODE_DECIPHER)
    """

    output = ""

    # --- IMPLEMENTATION GOES HERE ---



    # --------------------------------

    return output


def uoc_aes(message, key):
    """
    Implements 1 block AES enciphering using a 256-bit key.

    :param message: string of 1 and 0s with the binary representation of the messsage, 128 char. long
    :param key: string of 1 and 0s with the binary representation of the key, 256 char. long
    :return: string of 1 and 0s with the binary representation of the ciphered message, 128 char. long
    """

    cipher_text = ""

    # --- IMPLEMENTATION GOES HERE ---


    # --------------------------------

    return cipher_text


def uoc_g(message):
    """
    Implements the g function.

    :param message: string of 1 and 0s with the binary representation of the messsage, 128 char. long
    :return: string of 1 and 0s, 256 char. long
    """

    output = ""

    # --- IMPLEMENTATION GOES HERE ---


    # --------------------------------

    return output


def uoc_naive_padding(message, block_len):
    """
    Implements a naive padding scheme. As many 0 are appended at the end of the message
    until the desired block length is reached.

    :param message: string with the message
    :param block_len: integer, block length
    :return: string of 1 and 0s with the padded message
    """

    output = ""

    # --- IMPLEMENTATION GOES HERE ---



    # --------------------------------

    return output


def uoc_mmo_hash(message):
    """
    Implements the hash function.

    :param message: a char. string with the message
    :return: string of 1 and 0s with the hash of the message
    """

    h_i = ""

    # --- IMPLEMENTATION GOES HERE ---




    # --------------------------------

    return h_i


def uoc_collision(prefix):
    """
    Generates collisions for uoc_mmo_hash, with messages having a given prefix.

    :param prefix: string, prefix for the messages
    :return: 2-element tuple, with the two strings that start with prefix and have the same hash.
    """

    collision = ("", "")

    # --- IMPLEMENTATION GOES HERE ---



    # --------------------------------

    return collision
