#!/usr/bin/env python3
'''Module to run elevation encoder reader
'''
import socket
import sys
import datetime

from datetime import timezone
from pathlib import Path
from os import getpid
from time import sleep

from common import is_writable

SERVER_IP = '192.168.10.13'
SERVER_PORT = 7
RECV_BUFLEN = 128*15
FILE_LEN = 1000000 # numbrer of packets per file
DIR_BASE = Path('.')
LOCK_PATH = Path('./el_enc.lock')
FNAME_FORMAT = 'el_%Y-%m%d-%H%M%S+0000.dat'
VERSION = 2021042901

HEADER_TXT = b'''Stimulator encoder data
Packet format: [HEADER 1][TS_LSB 4][TS_MSB 4][DATA 5][FOOTER 1]
\tENC : HEADER=0x99 FOOTER=0x66
\t\tDATA=[SEC][MIN][HOUR][DAY 2]
\tIRIG: HEADER=0x55 FOOTER=0xAA
\t\tDATA=[STATE 4][0x00]
'''


def path_checker(path):
    '''Path health checker
    '''
    if not path.exists():
        raise RuntimeError(f'Path {path} does not exist.')

    if not path.is_dir():
        raise RuntimeError(f'Path {path} is not a directory.')

    if not is_writable(path):
        raise RuntimeError(f'You do not have a write access to the path {path}')

def path_creator(dirpath, fmt=FNAME_FORMAT):
    '''Create path
    Parameters
    ----------
    dirpath: pathlib.Path
        Path to the base directory
    fmt: str
        Format of the filename

    Returns
    -------
    path: pathlib.Path
        Path to a new file
    '''
    utcnow = datetime.datetime.now(tz=timezone.utc)
    _d = dirpath.joinpath(f'{utcnow.year:04d}')
    _d = _d.joinpath(f'{utcnow.month:02d}')
    _d = _d.joinpath(f'{utcnow.day:02d}')
    _d.mkdir(exist_ok=True, parents=True)
    path = _d.joinpath(utcnow.strftime(fmt))
    if path.exists():
        raise RuntimeError(f'Filename collision: {path}.')
    return path


class StmEncReader:
    '''Class to read elevation data'''
    def __init__(self, ip_addr=SERVER_IP, port=SERVER_PORT, verbose=False,
                 lockpath=LOCK_PATH, path_base=DIR_BASE, file_len=FILE_LEN):
        self._verbose = verbose
        self._connected = False

        # Avoiding multiple launch
        self._lockpath = lockpath
        self._locked = False

        if lockpath.exists():
            raise RuntimeError(f'Locked: {lockpath}')

        if not is_writable(lockpath.parent):
            raise RuntimeError(f'No write access to {lockpath.parent}')

        with open(lockpath, 'w') as _f:
            _f.write(f'{getpid()}\n')

        self._locked = True

        # Connection data
        self._ip_addr = ip_addr
        self._port = port
        self._client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # For filler
        self._current_path = None
        self._path_base = path_base
        self._file_len = file_len
        self._res = self._file_len*15
        self._carry_over = b''
        self.ts_latest = 0
        self.state_latest = 0


    def __del__(self):
        self._eprint('Deleted.')
        self._close()
        if self._locked:
            self._lockpath.unlink()
        self._eprint('Fin.')

    def _eprint(self, errmsg):
        if self._verbose:
            sys.stderr.write(f'{errmsg}\r\n')

    def _connect(self):
        if self._connected:
            self._eprint('Already connected.')
        else:
            self._client.connect((self._ip_addr, self._port))
            sleep(1)
            self._connected = True

    def connect(self):
        '''Establish connection to Zybo'''
        self._connect()

    def _close(self):
        if self._connected:
            self._client.close()
        else:
            self._eprint('Already closed.')

    def close(self):
        '''Close connection to Zybo'''
        self._close()
        self._current_path = None

    def _tcp_write(self, data):
        if self._connected:
            self._client.sendall(data)
        else:
            self._eprint('Not connected.')

    def loop(self, length=FILE_LEN, path=None):
        '''Start infinite loop of measurement
        Parameters
        ----------
        length: int
            Number of packets to read
        path: pathlib.Path or None, default None
            Path to the parent directory.
        '''
        if path is not None:
            path = Path(path)
            path_checker(path)

        self._eprint('Lets start')
        self._connect()
        try:
            while True:
                if path is None:
                    self.get_write(length)
                else:
                    self.get_write(length, path_creator(path))

        except KeyboardInterrupt:
            self._eprint('KeyboardInterrupt.')
            self._eprint('TCP connection aborted.')
            self._close()
            self._eprint('Fin.')

    def _write_header(self, path):
        current_time = datetime.datetime.now()

        with open(path, 'wb') as file_desc:
            # HEADER
            header = b''
            header += b'256\n' # 4 bytes, 256 is the length of the header

            # 4 bytes, version number of the logger software
            header += VERSION.to_bytes(4, 'little', signed=False)
            utime = current_time.timestamp()
            utime_int = int(utime)

            # 4 bytes, integer part of the current time in unix time
            header += utime_int.to_bytes(4, 'little', signed=False)
            # microseconds
            header += int((utime - utime_int)*1e6).to_bytes(4, 'little', signed=False)
            header += HEADER_TXT
            res = 256 - len(header)
            if res < 0:
                raise Exception('HEADER TOO LONG')
            header += b' '*res # adjust header size with white spaces

            file_desc.write(header)


    def get_write(self, data_num, path=None):
        '''Get data and write it to a file
        Parameters
        ----------
        data_num: int
            Number of packets to read
        path: pathlib.Path or None, default None
            Path to the file
        '''
        if not self._connected:
            raise RuntimeError('Not connected.')

        rest = 15*data_num
        current_time = datetime.datetime.now()
        if path is None:
            path = Path('.').joinpath(current_time.strftime(FNAME_FORMAT))

        self._write_header(path)

        with open(path, 'wb') as file_desc:
            while rest > 0:
                recv_num = RECV_BUFLEN if (rest > RECV_BUFLEN) else rest
                data = self._client.recv(recv_num)
                file_desc.write(data)
                rest = rest - len(data)

    def fill(self):
        '''Fill current file
        '''
        # initialization
        if self._current_path is None:
            self._current_path = path_creator(self._path_base)
            self._write_header(self._current_path)
            self._res = self._file_len*15

        # body
        recv_num = RECV_BUFLEN if (self._res > RECV_BUFLEN) else self._res
        data = self._client.recv(recv_num)
        self._res -= len(data)

        with open(self._current_path, 'ab') as file_desc:
            file_desc.write(data)

        if self._res <= 0:
            self._current_path = None

        # analyzer
        tmpd = self._carry_over + data
        tmpr = len(tmpd) % 15
        self._carry_over = tmpd[tmpr:]

        pnum = int(len(tmpd)/15)

        for i in range(pnum):
            packet = tmpd[15*i:15*(i+1)]
            header = packet[0]
            ts_lsb = int.from_bytes(packet[1:5], 'little')
            ts_msb = int.from_bytes(packet[5:9], 'little')
            timestamp = ts_lsb + (ts_msb << 32)
            status = int.from_bytes(packet[9:13], 'little')
            footer = packet[14]
            if (header == 0x99) and (footer == 0x66):
                self.ts_latest = timestamp
                self.state_latest = status


def main():
    '''Main function to boot infinite loop'''
    elread = StmEncReader(verbose=True)

    # Filler loop
    try:
        elread.connect()
        while True:
            elread.fill()
            sleep(0.1)
    except KeyboardInterrupt:
        print('fin.')

if __name__ == '__main__':
    main()
