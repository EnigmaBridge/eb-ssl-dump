#!/usr/bin/env python
# -*- coding: utf-8 -*-

import math
import logging
import coloredlogs
from mpmath import mp
import mpmath

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)

mp.dps = 150  # 100 decimal places precision

R = long('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16)
Rlog = math.log(R, 2)
Rlog_exact2 = mpmath.log(R, 2)
logger.info('R: %s, log: %s, exactmp: %s' % (R, Rlog, Rlog_exact2))

align_8 = True
best_i = None
best_a = None
min_dif = None
for i in range(1, 1024):
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

    logger.info('...a: %s, denominator: 2^%s, \ndiflog: %s %s' % (a, i, Rdiflog, 'X' if i%8 == 0 else ''))

    if min_dif is None or min_dif > abs(Rdiflog) and (not align_8 or i % 8 == 0):
        min_dif = Rdiflog
        best_a = a
        best_i = i

logger.info('Terminated, best diff: %s, best a: %s, best denominator: 2^%s' % (min_dif, best_a, best_i))


