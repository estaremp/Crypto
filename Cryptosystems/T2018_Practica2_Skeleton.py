#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES

MODE_CIPHER = 0
MODE_DECIPHER = 1

# --- IMPLEMENTATION GOES HERE ---------------------------------------------
#  Student helpers (functions, constants, etc.) can be defined here, if needed

from functools import reduce
import binascii
from random import *

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

    #slice input parameters into LSFR states
    state_1 = params_pol_0[1]
    state_2 = params_pol_1[1]
    state_3 = params_pol_2[1]
    
    #initial bit index of each LSR
    gates_1 = len(state_1)
    gates_2 = len(state_2)
    gates_3 = len(state_3)
    
    #LSFR polynomial
    conn_1 = params_pol_0[0]
    conn_2 = params_pol_1[0]
    conn_3 = params_pol_2[0]
    
    if (clocking_bits[0]>=gates_1) or (clocking_bits[1]>=gates_2) or (clocking_bits[2]>=gates_3):
        print("ERROR: Clocking bits are not valid for this set up.")
    
    i = 0
    #loop for as many needed bits in the sequence
    while (i<output_bits):
        
        #xor last bits of the state of each LSFR
        z = state_1[0]^state_2[0]^state_3[0]
        sequence.append(z)
        
        #check state of clocking bits
        clck = [state_1[-clocking_bits[0]-1],state_2[-clocking_bits[1]-1],state_3[-clocking_bits[2]-1]]
        
        #find what the majority says
        vote = max(set(clck), key = clck.count)

        #when part of the majority, displace one bit the LSFR state
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
    
    #define the polynomial list
    conn_LFSR1 = [0]*19
    conn_LFSR2 = [0]*22
    conn_LFSR3 = [0]*23
    
    #define coefficients for each LFSR
    conn_LFSR1[-19]=1
    conn_LFSR1[-18]=1
    conn_LFSR1[-17]=1
    conn_LFSR1[-14]=1

    conn_LFSR2[-22]=1
    conn_LFSR2[-21]=1
    
    conn_LFSR3[-23]=1
    conn_LFSR3[-22]=1
    conn_LFSR3[-21]=1
    conn_LFSR3[-8]=1
    
    #put them together
    params_LFSR1 = [conn_LFSR1,initial_state_0]
    params_LFSR2 = [conn_LFSR2,initial_state_1]
    params_LFSR3 = [conn_LFSR3,initial_state_2]
    
    #define clocking bits indices
    clck_A = [8,10,10]
    
    #encode
    if mode==0:
        #message to bin
        msg_bin = [int(m) for m in bin(int.from_bytes(message.encode(),'big'))[2:]]
        msg_bin.insert(0,0)
        
        #generate a5 sequence
        generated_seq = uoc_ext_a5_pseudo_random_gen(params_LFSR1, params_LFSR2, params_LFSR3, clck_A, len(msg_bin))
        
        #xor seq and message to encrypt and parse it to string for output
        output = ''.join(str(m) for m in [aa^bb for aa,bb in zip(generated_seq,msg_bin)])

    #decode
    if mode==1:
        #generate a5 sequence
        generated_seq = uoc_ext_a5_pseudo_random_gen(params_LFSR1, params_LFSR2, params_LFSR3, clck_A, len(message))
        
        #xor seq and message to decrypt
        decoded_msg = int(''.join(str(m) for m in [aa^bb for aa,bb in zip(generated_seq,[int(s) for s in message])]),2)
        
        #parse from int to bytes, and from bytes to an ascii string
        output = decoded_msg.to_bytes((decoded_msg.bit_length() + 7) // 8, 'big').decode()

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

    block_size=16
    
    #string of bits to bytes
    k = int(key,2).to_bytes(2*block_size, 'big')
    m = int(message,2).to_bytes(block_size, 'big')
    
    #encrypt
    aes = AES.new(k,AES.MODE_ECB)
    cipher_text = ''.join(str(c) for c in format(int.from_bytes(aes.encrypt(m),'big'),'0128b'))

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

    #concatenate two copies of the message
    output = (message + message)
    
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
    
    padding = ''
    size_msg = (len(message)*8)

    #create string of 0's the size of the block-len minus the division remainder
    if (size_msg % block_len != 0):
        padding = ''.join('0' for i in range(block_len - size_msg % block_len))
    
    #concatenate message bits with padding list o 0's
    output = ''.join(str(c) for c in format(int.from_bytes(message.encode(),'big'),'0'+str(size_msg)+'b')) + padding
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
    
    #block size of our hash
    block_size = 128
    
    #define IV
    h_i = [1 for i in range(block_size)]

    #add message padding if not multiple of 128
    padded_msg = [int(m) for m in uoc_naive_padding(message, block_size)]
    
    #divide message into blocks
    num_blocks = int(len(padded_msg)/block_size)
    
    block = []
    for i in range(num_blocks):
        block.append(padded_msg[i*block_size:i*block_size+block_size])
    
    #main loop
    for i in range(num_blocks):
        #generate key
        key = uoc_g(''.join(str(h) for h in h_i))
        #xor aes output with previous hash
        h_i = [aa^bb for aa,bb in zip(h_i,[int(a) for a in uoc_aes(''.join(str(b) for b in block[i]),key)])]

    #parse hash to string
    h_i = ''.join(str(h) for h in h_i)

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

    size_msg = len(prefix)*8
    block_len = 128
    
    #check how much left there is for the message to fill the last block
    whats_left = int((block_len - size_msg % block_len)/8)
    
    #generate two different random numbers within that range
    null_a = randint(2,whats_left)
    null_b = randint(1,null_a-1)
    
    #add some Null characters
    msg_a = prefix + ''.join('\0' for i in range(null_a))
    msg_b = prefix + ''.join('\0' for i in range(null_b))

    collision = (msg_a,msg_b)
    
    # --------------------------------

    return collision
