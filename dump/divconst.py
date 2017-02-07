#!/usr/bin/env python
# -*- coding: utf-8 -*-

import math
import logging
import coloredlogs
import argparse
from mpmath import mp
import mpmath
import random

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


def rand_test(samples, a, k, r):
    """
    Tests samples * a >> k == samples // r
    :param samples:
    :param a:
    :param k:
    :return:
    """
    succ = 0
    min_bit_fail, min_bit_fail_val = None, None
    max_bit_fail, max_bit_fail_val = None, None
    a, k, r = long(a), long(k), long(r)
    for x in samples:
        if ((x * a) >> k) == (x // r):
            succ += 1
        else:
            was_set = False
            if min_bit_fail_val is None or min_bit_fail_val > x:
                min_bit_fail_val = x
                was_set = True
            if max_bit_fail_val is None or max_bit_fail_val < x:
                max_bit_fail_val = x
                was_set = True

            if not was_set:
                continue

            lg = mpmath.ceil(mpmath.log(x, 2))
            if min_bit_fail is None or min_bit_fail > lg:
                min_bit_fail = lg
            if max_bit_fail is None or max_bit_fail < lg:
                max_bit_fail = lg

    return succ, min_bit_fail, max_bit_fail


def build_samples(R, maxbit):
    """
    Builds array of testing samples
    :param R:
    :param maxbit:
    :return:
    """
    samples = []

    i = 1
    while 8*i <= maxbit:
        samples += [random.randint(1, (2 ** (8 * i)) - 1) for _ in range(100)]
        if i < 4:
            i += 1
        else:
            i *= 2

    # R-products
    Rlog2 = mpmath.ceil(mpmath.log(R, 2))
    i = 1
    while (8 * i + Rlog2) <= maxbit:
        samples += [R * long(random.randint(1, (2 ** (8 * i)) - 1)) for _ in range(100)]
        if i < 4:
            i += 1
        else:
            i += 2

    return samples


#
# Argument parsing
#

parser = argparse.ArgumentParser(description='Division by a constant approximator')
parser.add_argument('--num', dest='num', default='FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
                    help='Number to approximate')
parser.add_argument('--dps', dest='dps', default=100, type=int,
                    help='Decimal places precision in floating point arithmetics')
parser.add_argument('--top', dest='top', default=1024, type=int,
                    help='Top exponent to try')
parser.add_argument('--align', dest='align', default=False, action='store_const', const=True,
                    help='Align shift to 8bits')
parser.add_argument('--floor', dest='floor', default=False, action='store_const', const=True,
                    help='Floor A')
parser.add_argument('--ceil', dest='ceil', default=False, action='store_const', const=True,
                    help='Ceil A')
parser.add_argument('--step', dest='step', default=5, type=int,
                    help='Step of the precision loop')
parser.add_argument('--maxbit', dest='maxbit', default=64*8, type=int,
                    help='Max bit register of the division subject')
args = parser.parse_args()

align_8 = args.align
R_long = long(args.num, 16)
R = mpmath.mpmathify(R_long)

# Testing samples - for trial division test of the approximation vs. constant
samples = build_samples(R_long, args.maxbit)
logger.info('R: %s = %s, max bit register: %d = %s B' % (R_long, hex(R_long), args.maxbit, args.maxbit / 8.0))

for dps in range(5, args.dps, args.step):
    mp.dps = dps
    Rlog = math.log(R, 2)
    Rlog_exact2 = mpmath.log(R, 2)
    logger.info('DPS: %d, R: %s, log: %s, \n\texactmp: %s' % (dps, R, Rlog, Rlog_exact2))

    best_i = None
    best_a = None
    best_tests = 0
    min_dif = 10**9999
    for i in range(1, args.top):
        if align_8 and i % 8 != 0:
            continue

        power = mpmath.power(2, i)

        # 1/R = a / 2^(k)
        #   R = 2^k / a
        #   a = 2^k / R
        if power < R:
            continue

        # http://mpmath.org/doc/current/general.html#fdiv
        a = mpmath.fdiv(power, R, dps=150)
        if args.floor:
            a = mpmath.floor(a)
        elif args.ceil:
            a = mpmath.ceil(a)
        else:
            a = mpmath.nint(a)

        # a = long(round(power / float(R)))
        # R = 2^k / a
        # log R = k - log a
        # Rlogexact - (k - log(a))

        Rdiflog = mpmath.fabs(Rlog_exact2 - (i - mpmath.log(a, 2)))
        # logger.info('...a: %s, denominator: 2^%s, \ndiflog: %s %s' % (a, i, Rdiflog, 'X' if i%8 == 0 else ''))

        tests, mibf, mabf = rand_test(samples, a, i, R)

        if min_dif > abs(Rdiflog) or (best_tests < abs(tests)):
        # if min_dif > abs(Rdiflog) or (min_dif == abs(Rdiflog) and best_tests < abs(tests)):
        # if min_dif > abs(Rdiflog):
        # if best_tests < abs(tests):
            min_dif = Rdiflog
            best_a = long(a)
            best_tests = tests
            best_i = i

    # Precision test:
    R_prec = mpmath.fdiv(2**best_i, best_a) - R

    # R * 1/R
    R_self = (long(R) * long(best_a)) >> best_i
    R_self2 = (long(R*2) * long(best_a)) >> best_i
    R_self3 = (long(R*3) * long(best_a)) >> best_i
    R_self4 = (long(R*4) * long(best_a)) >> best_i
    R_self12345 = (long(R*12345) * long(best_a)) >> best_i
    R_self65537 = (long(R*65537) * long(best_a)) >> best_i

    # Representation
    a_bits = mpmath.ceil(mpmath.log(best_a, 2))
    a_hex = hex(best_a)[2:]
    k_hex = hex(best_i)[2:]
    if a_hex.endswith('L'):
        a_hex = a_hex[:-1]
    if k_hex.endswith('L'):
        k_hex = k_hex[:-1]

    if len(a_hex) & 1 == 1:
        a_hex = '0'+a_hex

    # Byte array
    ln = len(a_hex)
    a_byte = []
    for i in range(0, ln, 2):
        cur = a_hex[i:i+2]
        a_byte.append(cur)

    a_byte = ', '.join(['(byte)0x'+x for x in a_byte])

    succ, mibf, mabf = rand_test(samples=samples, a=best_a, k=best_i, r=R)

    print(''
          '\tdiff           %s, \n'
          '\tbest a:        %s, \n'
          '\tbitsize a:     %s, = %s B \n'
          '\tbest denom:    2^%s, hex=0x%s, /8 = %s\n'
          '\ta hex:         0x%s, \n'
          '\ta byte:        byte[] a = new byte[] {%s}; \n'
          '\tapprox - R:    %s\n'
          '\tR-approx-test: %s, %s, %s, %s, %s, %s\n'
          '\tsucc tests:    %s / %s, min bits fail: %s, max bits fail: %s\n'
          % (min_dif, best_a, a_bits, math.ceil(a_bits/8.0),
             best_i, k_hex, best_i/8.0, a_hex, a_byte, R_prec,
             R_self, R_self2, R_self3, R_self4, R_self12345, R_self65537,
             succ, len(samples), mibf, mabf))


