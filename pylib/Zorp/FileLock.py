import fcntl

from Zorp import log

class FileLock(object):
    '''
    File based locking, usable as a context manager
    '''

    def __init__(self, filename=None):
        self.filename = filename
        self.lock_fd = self._open_lockfile(filename)

    def _open_lockfile(self, filename):
        try:
            try:
                fd = open(filename, 'r+')
            except IOError:
                fd = open(filename, 'w')
            return fd
        except IOError, e:
            log(None, CORE_ERROR, 3, "Error opening lock file; file='%s', error='%s'", (e.filename, e.strerror))

    def acquire(self):
        self._lock_file_exclusively(self.lock_fd)

    def release(self):
        self._unlock_file(self.lock_fd)

    def _lock_file_exclusively(self, fd):
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _unlock_file(self, fd):
        fcntl.flock(fd, fcntl.LOCK_UN)

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
        return False
