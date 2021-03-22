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
RECV_BUFLEN = 128*12
FILE_LEN = 1000000 # numbrer of packets per file
DIR_BASE = Path('.')
LOCK_PATH = Path('./el_enc.lock')
FNAME_FORMAT = 'el_%Y-%m%d-%H%M%S+0000.dat'
VERSION = 2021032201

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
    def __init__(self, ip_addr=SERVER_IP, port=SERVER_PORT, verbose=False, lockpath=LOCK_PATH):
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

    def _close(self):
        if self._connected:
            self._client.close()
        else:
            self._eprint('Already closed.')

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

            # BODY
            while rest > 0:
                recv_num = RECV_BUFLEN if (rest > RECV_BUFLEN) else rest
                data = self._client.recv(recv_num)
                file_desc.write(data)
                rest = rest - len(data)


def main():
    '''Main function to boot infinite loop'''
    elread = StmEncReader(verbose=True)
    elread.loop(path=DIR_BASE)

if __name__ == '__main__':
    main()
