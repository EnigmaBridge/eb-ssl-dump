#!/usr/bin/env python
# -*- coding: utf-8 -*-

import math
import logging
import coloredlogs
import argparse
from mpmath import mp
import mpmath

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


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
args = parser.parse_args()


R = mpmath.mpmathify(long(args.num, 16))
mp.dps = args.dps
Rlog = math.log(R, 2)
Rlog_exact2 = mpmath.log(R, 2)
logger.info('R: %s, log: %s, exactmp: %s' % (R, Rlog, Rlog_exact2))


align_8 = args.align
best_i = None
best_a = None
min_dif = None
for i in range(1, args.top):
    power = mpmath.power(2, i)

    # 1/R = a / 2^(k)
    #   R = 2^k / a
    #   a = 2^k / R
    if power < R:
        continue

    # http://mpmath.org/doc/current/general.html#fdiv
    a = mpmath.nint(mpmath.fdiv(power, R, dps=150))
    # a = long(round(power / float(R)))

    # R = 2^k / a
    # log R = k - log a
    # Rlogexact - (k - log(a))
    Rdiflog = mpmath.fabs(Rlog_exact2 - (i - mpmath.log(a, 2)))
    #logger.info('...a: %s, denominator: 2^%s, \ndiflog: %s %s' % (a, i, Rdiflog, 'X' if i%8 == 0 else ''))

    if min_dif is None or min_dif > abs(Rdiflog) and (not align_8 or i % 8 == 0):
        min_dif = Rdiflog
        best_a = long(a)
        best_i = i

# Precision test:
R_prec = mpmath.fdiv(2**best_i, best_a) - R

# R * 1/R
R_self = (long(R) * long(best_a)) >> best_i
R_self2 = (long(R*2) * long(best_a)) >> best_i
R_self3 = (long(R*3) * long(best_a)) >> best_i
R_self4 = (long(R*4) * long(best_a)) >> best_i

logger.info('Terminated, best diff: %s, \nbest a: %s, \nbest denominator: 2^%s, \nR-prec: %s\nR-self: %s, %s, %s, %s'
            % (min_dif, best_a, best_i, R_prec, R_self, R_self2, R_self3, R_self4))


