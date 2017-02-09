#!/usr/bin/env python
# -*- coding: utf-8 -*-

import math
import logging
import argparse


def to_hex(num):
    """
    Number to hex string, byte aligned from left
    :param num:
    :return:
    """
    a_hex = '%x' % num
    if len(a_hex) & 1 == 1:
        a_hex = '0'+a_hex
    return a_hex


def to_bytearray(num):
    """
    Converts long number to byte array
    :param num:
    :return:
    """
    num_hex = to_hex(num)

    # Byte array
    ln = len(num_hex)
    a_byte = []
    for i in range(0, ln, 2):
        cur = num_hex[i:i+2]
        a_byte.append(cur)

    a_byte = ', '.join(['(byte)0x'+x for x in a_byte])
    return 'new byte[] {%s};' % a_byte


parser = argparse.ArgumentParser(description='Converts numbers to byte array in Java')
parser.add_argument('--hex', dest='hex', default=False, action='store_const', const=True,
                    help='If the input number is hex-coded')
parser.add_argument('numbers', nargs=argparse.ZERO_OR_MORE, default=[],
                    help='numbers to convert to byte array')
args = parser.parse_args()

for num in args.numbers:
    val = long(num, 16 if args.hex else 10)
    print(to_bytearray(val))

