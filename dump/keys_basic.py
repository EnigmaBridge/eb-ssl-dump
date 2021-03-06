import base64
import types
import struct
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.py3compat import *
from Crypto.Util.number import long_to_bytes, bytes_to_long, size, ceil_div


__author__ = 'dusanklinec'


def long_bit_size(x):
    return size(x)


def long_byte_size(x):
    return ceil_div(long_bit_size(x), 8)


def bytes_to_byte(byte, offset=0):
    return struct.unpack('>B', byte[offset:offset+1])[0]


def byte_to_bytes(byte):
    return struct.pack('>B', int(byte) & 0xFF)


def left_zero_pad(inp, ln):
    real_len = len(inp)
    if real_len >= ln:
        return inp
    return ('0'*(ln-real_len)) + inp


def compute_key_mask(n):
    """
    Computes public modulus key mask.
    2nd-7th most significant bit of modulus | 2nd least significant bit of modulus | modulus mod 3 | modulus_length_in_bits mod 2

    :param n:
    :return:
    """
    if not isinstance(n, types.LongType):
        raise ValueError('Long expected')
    mask = ''

    buff = long_to_bytes(n)

    msb = long(bytes_to_byte(buff[0]))
    bit_section = (msb >> 1) & 0x3f
    mask += left_zero_pad(bin(bit_section)[2:], 6)
    mask += '|'

    lsb = long(bytes_to_byte(buff[-1:]))
    mask += bin((lsb & 0x2) >> 1)[2:]
    mask += '|'

    mask += str(n % 3)
    mask += '|'

    mask += str(long_bit_size(n) % 2)
    return mask


def generate_pubkey_mask_src(pmsb, plsb, prem, plen):
    mask = ''

    mask += left_zero_pad(bin(pmsb)[2:], 6)
    mask += '|'

    mask += bin(plsb)[2:]
    mask += '|'

    mask += str(prem)
    mask += '|'

    mask += str(plen)
    return mask


def generate_pubkey_mask():
    """
    Generates public key mask space, defines ordering on the mask.
    Is crucial to preserve the ordering among invocations of the script.
    Producing results with different ordering on masks can cause troubles an inconsistencies.

    2nd-7th most significant bit of modulus | 2nd least significant bit of modulus | modulus mod 3 | modulus_length_in_bits mod 2
    :return:
    """
    # for plen in range(0,2):
    #     for prem in range(1,3):
    for prem in range(1,3):
        for plen in range(0,2):
            for plsb in range(0,2):
                for pmsb in range(0, 0x40):
                    yield generate_pubkey_mask_src(pmsb=pmsb, plsb=plsb, prem=prem, plen=plen)


def project_mask(mask, mask_mask):
    """
    Selects only particular part of the mask
    :param mask:
    :param mask_mask: list of indices
    :return:
    """
    if mask_mask is None:
        return mask
    res_mask = ''
    for idx in mask_mask:
        res_mask += mask[idx]
    return res_mask


def aggregate_mask(data, mask, mask_mask=None, init_res=0.0, merger=lambda x,y: x+y):
    """
    Computes aggregation over masks:
    e.g., 000000|0|0|0 -> SUM where mask starts with 00000
    :param data: mask -> value
    :param mask:
    :param mask_mask: list of indices
    :return:
    """
    res = init_res
    proj_mask = project_mask(mask, mask_mask)
    if proj_mask == mask:
        return data[mask]

    for cur_mask in data:
        if project_mask(cur_mask, mask_mask) == proj_mask:
            res = merger(res, data[cur_mask])

    return res


def generate_pubkey_mask_indices():
    """
    Generate index of the mask - ordinal number in the ordering defined by a generator.
    Generates also 2D breakdown for the 2D charts
    :return:
    """

    # mask index
    mask_map = {}
    mask_max = 0

    # mask index 2D breakdown
    mask_gen = generate_pubkey_mask()
    mask_map_x = {}
    mask_map_last_x = 0
    mask_map_y = {}
    mask_map_last_y = 0
    for idx, mask in enumerate(mask_gen):
        parts = [x.replace('|', '') for x in mask.split('|', 1)]
        x = parts[0]
        y = parts[1]
        if x not in mask_map_x:
            mask_map_x[x] = mask_map_last_x
            mask_map_last_x += 1

        if y not in mask_map_y:
            mask_map_y[y] = mask_map_last_y
            mask_map_last_y += 1

        mask_map[mask] = idx
        mask_max = idx
    return mask_map, mask_max, mask_map_x, mask_map_y, mask_map_last_x-1, mask_map_last_y-1


if __name__ == "__main__":
    print compute_key_mask(888888888L)

