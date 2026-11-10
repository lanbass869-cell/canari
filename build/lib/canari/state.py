# -*- coding: utf-8 -*-
import json, os, time

class FileLock:
    def __init__(self, path, timeout=30.0):
        self.path = path + '.lock'
        self.timeout = timeout
        self._fd = None
    def __enter__(self):
        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        self._fd = open(self.path, 'a+b')
        t0 = time.time()
        while True:
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(self._fd.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except (IOError, OSError):
                if time.time() - t0 >= self.timeout:
                    self._fd.close()
                    raise TimeoutError('lock %s after %.0fs' % (self.path, self.timeout))
                time.sleep(0.5)
    def __exit__(self, *exc):
        if self._fd:
            try:
                if os.name == 'nt':
                    import msvcrt
                    self._fd.seek(0)
                    msvcrt.locking(self._fd.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._fd.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            self._fd.close()
            self._fd = None
        return False

class StateStore:
    def __init__(self, state_path):
        self.path = state_path
        self._data = self._load()
    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {'last_run_at': None, 'run_count': 0, 'components': {}}
    def save(self):
        self._data['last_run_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        self._data['run_count'] = self._data.get('run_count', 0) + 1
        tmp = self.path + '.tmp'
        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(self._data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)
    def get_component(self, name):
        return self._data.get('components', {}).get(name)
    def set_component(self, name, version, sha256, digest, meta=None):
        entry = {'version': version, 'sha256': sha256, 'attestation_digest': digest}
        if meta:
            entry['meta'] = meta  # maintainers/homepage snapshot for H2 anomaly (BUG-75)
        self._data.setdefault('components', {})[name] = entry
        return entry
    def diff(self, current, prev=None):
        prev = prev if prev is not None else self._data.get('components', {})
        new, changed, unchanged, removed = [], [], [], []
        for name, info in current.items():
            p = prev.get(name)
            if p is None:
                new.append(name)
            elif p.get('sha256') != info.get('sha256'):
                changed.append(name)
            else:
                unchanged.append(name)
        for name in prev:
            if name not in current:
                removed.append(name)
        return {'new': new, 'changed': changed, 'unchanged': unchanged, 'removed': removed}
    @property
    def run_count(self):
        return self._data.get('run_count', 0)
    @property
    def is_first_run(self):
        return self._data.get('run_count', 0) == 0
