#!/usr/bin/env python3
import sys
from binascii import unhexlify, hexlify

def read_hex_file(path):
    s = open(path,'r').read().strip()
    s = ''.join(s.split())
    return unhexlify(s)

def read_varint(b, off):
    v = b[off]
    if v < 0xfd:
        return v, 1
    if v == 0xfd:
        return int.from_bytes(b[off+1:off+3],'little'), 3
    if v == 0xfe:
        return int.from_bytes(b[off+1:off+5],'little'), 5
    return int.from_bytes(b[off+1:off+9],'little'), 9

def dump_pushes(script):
    i = 0
    pushes = []
    while i < len(script):
        op = script[i]
        if op == 0x76 or op == 0xa9 or op == 0x88 or op == 0xac:
            pushes.append((i, op, 0, b''))
            i += 1
            continue
        if op <= 75:
            ln = op
            data = script[i+1:i+1+ln]
            pushes.append((i, op, ln, data))
            i += 1+ln
            continue
        if op == 0x4c: # OP_PUSHDATA1
            ln = script[i+1]
            data = script[i+2:i+2+ln]
            pushes.append((i, op, ln, data))
            i += 2+ln
            continue
        if op == 0x4d:
            ln = int.from_bytes(script[i+1:i+3],'little')
            data = script[i+3:i+3+ln]
            pushes.append((i, op, ln, data))
            i += 3+ln
            continue
        if op == 0x4e:
            ln = int.from_bytes(script[i+1:i+5],'little')
            data = script[i+5:i+5+ln]
            pushes.append((i, op, ln, data))
            i += 5+ln
            continue
        # unknown opcode
        pushes.append((i, op, None, b''))
        i += 1
    return pushes

def inspect(txbytes):
    off = 0
    print('txlen:', len(txbytes))
    version = int.from_bytes(txbytes[off:off+4],'little'); off+=4
    print('version:', version, 'offset:', 0)
    vin_cnt, vlen = read_varint(txbytes, off); print('vin_count:', vin_cnt, 'varint_len:', vlen, 'offset:', off); off += vlen
    for vi in range(vin_cnt):
        prev = txbytes[off:off+32]; off+=32
        prev_index = int.from_bytes(txbytes[off:off+4],'little'); off+=4
        print(f'vin[{vi}] prev_hash:', hexlify(prev[::-1]).decode(), 'prev_index:', prev_index, 'offset_now:', off)
        script_len, vlen = read_varint(txbytes, off); off += vlen
        script = txbytes[off:off+script_len]
        print(' vin script_len:', script_len, 'varint_len:', vlen, 'script_hex:', hexlify(script).decode())
        pushes = dump_pushes(script)
        for p in pushes:
            idx, op, ln, data = p
            print('  push at', idx, 'op=0x%02x' % op, 'len=', ln, 'data=', hexlify(data).decode())
        off += script_len
        seq = int.from_bytes(txbytes[off:off+4],'little'); off+=4
        print(' vin seq:', seq, 'offset_after_vin:', off)
    vout_cnt, vlen = read_varint(txbytes, off); print('vout_count:', vout_cnt, 'varint_len:', vlen, 'offset:', off); off+=vlen
    for vo in range(vout_cnt):
        value = int.from_bytes(txbytes[off:off+8],'little'); off+=8
        script_len, vlen = read_varint(txbytes, off); off+=vlen
        script = txbytes[off:off+script_len]; off+=script_len
        print(f'vout[{vo}] value_satoshis:{value} script_len:{script_len} script_hex:{hexlify(script).decode()}')
    locktime = int.from_bytes(txbytes[off:off+4],'little'); off+=4
    print('locktime:', locktime, 'final_offset:', off)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: inspect_tx.py /path/to/tx.hex')
        sys.exit(1)
    tx = read_hex_file(sys.argv[1])
    inspect(tx)
