#!/usr/bin/env python
# -*- coding: utf-8 -*-


# --- IMPLEMENTATION GOES HERE ---------------------------------------------
#  Student helpers (functions, constants, etc.) can be defined here, if needed

#MARTA PASCUAL ESTARELLAS - PRACTICA 1 - CRIPTOGRAFIA, 2018

#import randint from random module to generate pseudo-random integers
from random import randint

# --------------------------------------------------------------------------


def uoc_railfence_genkey(max_rails=10, num_holes=0, max_hole_pos=100):
    """
    Generates a random key for the modified rail fence cipher. A key is a two-element tuple:
    - the first element is an integer with the number of rails
    - the second element is a list of holes. Each hole is a tuple (rail number, column number)

    :param max_rails: optional parameter (defaults to 10), maximum number of rails.
    :param num_holes: optional parameter (detaults to 0), number of holes to include in the fence.
    :param max_hole_pos: optional parameter (defaults to 100), maximum column value for holes.
    :return:
    """

    key = (None, [])

    # --- IMPLEMENTATION GOES HERE ---

    #generate a random number of rails between 2 and the maximum allowed
    rails = randint(2,max_rails)
    
    #array containing the holes positions (x,y)
    holes = []
    
    i = 0
    #generate as many random pairs (x,y) of holes as the inputed arg indicates
    while i < num_holes:
        hole = (randint(0,rails-1),randint(0,max_hole_pos-1))
        #take care for possible repetitions (we don't want them)
        if hole in holes:
            continue
        holes.append(hole)
        i += 1

    #write key with the desired format, rails and holes positions
    key = (rails,holes)

    # --------------------------------

    return key


def uoc_railfence_encrypt(message, key):
    """
    Ciphers the message with the key, using the modified rail fence cipher.

    :param message: string, message to cipher (may contain upper and lower case letters, spaces,
        and basic symbols (!, -, and _)
    :param key: rail fence cipher key, as returned by uoc_railfence_genkey
    :return: string, ciphered message
    """

    ciphertext = ''

    # --- IMPLEMENTATION GOES HERE ---

    #for the matrix fence we need rows, columns and hole positions
    rows = key[0]
    holes = key[1]
    
    #we know that we won't need more columns than characters of the message+number of holes (upper limit)
    cols = len(message)+len(holes)
    
    #generate an empty (all zeros) matrix of the required size
    mat = [[0 for x in range(cols)] for y in range(rows)]

    j = 0
    i = 0
    m = 0
    #for all columns and as long as we still have characters to allocate in our fance
    while j < cols and m < len(message):
        pos = (i,j)
        #if the position is not occupied by a hole, then write a character from the message
        if pos not in holes:
            mat[pos[0]][pos[1]] = message[m]
            m += 1
        #impose zig zag behaviour on the row indices to obtain the right positions
        if i==0:
            k = 1
        elif i==(rows-1):
            k = -1
        j += 1
        i += k

    #read the fence elements distinct to 0 by rows to obtain the cyphertext
    for i in range(rows):
        for j in range(cols):
            elem = mat[i][j]
            if elem!=0:
                ciphertext=ciphertext+elem

    # --------------------------------
    return ciphertext


def uoc_railfence_decrypt(ciphertext, key):
    """
    Deciphers the ciphertext with the key, , using the modified rail fence cipher.
    :param ciphertext: string, message to decipher (may contain upper and lower case letters, spaces,
        and basic symbols (!, -, and _)
    :param key: rail fence cipher key, as returned by uoc_railfence_genkey
    :return: string, deciphered message
    """

    plaintext = ''

    # --- IMPLEMENTATION GOES HERE ---

    #generate again a matrix where to allocate all our characters and holes
    rows = key[0]
    holes = key[1]
    cols = len(ciphertext)+len(holes)

    mat = [[0 for x in range(cols)] for y in range(rows)]
    
    j = 0
    i = 0
    m = 0
    p = []
    #find all the suitable positions to fill the fence excluding the ones occupied by holes
    while j < cols and m < len(ciphertext):
        pos = (i,j)
        if pos not in holes:
            p.append(pos)
            m += 1
        if i==0:
            k = 1
        elif i==(rows-1):
            k = -1
        j += 1
        i += k

    #sort the positions by increasing index of rows
    p=sorted(p, key=lambda x: x[0])

    m = 0
    #fill the suitable positions of each row with the characters from the ciphertext
    while m < len(ciphertext):
        pos = p[m]
        mat[pos[0]][pos[1]] = ciphertext[m]
        m += 1

    #read the fence elements distinct to 0 by columns to obtain the message
    for j in range(cols):
        for i in range(rows):
            elem = mat[i][j]
            if elem!=0:
                plaintext=plaintext+elem
    # --------------------------------
    return plaintext
