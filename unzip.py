#!/usr/bin/env python3
#
##############################################################################
### NZBGET SCAN SCRIPT                                          ###

# Unzips zipped nzbs.
#
# NOTE: This script requires Python 3 to be installed on your system.
#       It requires also to install py7zr (https://pypi.org/project/py7zr/)

##############################################################################
### OPTIONS                                                                ###
### NZBGET SCAN SCRIPT                                          ###
##############################################################################

from __future__ import print_function
import os, zipfile, py7zr, tarfile, gzip, pickle, datetime, re, struct, locale, sys
import rarfile.rarfile as rarfile

from gzip import FEXTRA, FNAME

try:
    from urllib import unquote
except ImportError:
    from urllib.parse import unquote

if sys.version_info < (3, 0, 0):
    PY3 = False
    PY2 = True
else:
    PY3 = True
    PY2 = False


if PY2:
    if 'nt' == os.name:
        import ctypes

        class WinEnv:
            def __init__(self):
                pass

            @staticmethod
            def get_environment_variable(name):
                name = unicode(name)  # ensures string argument is unicode
                n = ctypes.windll.kernel32.GetEnvironmentVariableW(name, None, 0)
                result = None
                if n:
                    buf = ctypes.create_unicode_buffer(u'\0'*n)
                    ctypes.windll.kernel32.GetEnvironmentVariableW(name, buf, n)
                    result = buf.value
                return result

            def __getitem__(self, key):
                return self.get_environment_variable(key)

            def get(self, key, default=None):
                r = self.get_environment_variable(key)
                return r if r is not None else default

        env_var = WinEnv()
    else:
        class LinuxEnv(object):
            def __init__(self, environ):
                self.environ = environ

            def __getitem__(self, key):
                v = self.environ.get(key)
                try:
                    return v.decode(SYS_ENCODING) if isinstance(v, str) else v
                except (UnicodeDecodeError, UnicodeEncodeError):
                    return v

            def get(self, key, default=None):
                v = self[key]
                return v if v is not None else default

        env_var = LinuxEnv(os.environ)
else:
    class Py3Env(object):
        def __init__(self):
            pass

        def __getitem__(self, item):
            return os.environ.get(item)

        def get(self, key, default=None):
            if None is not default:
                return os.environ.get(key)
            return os.environ.get(key, default)

    env_var = Py3Env()


SYS_ENCODING = None
try:
    locale.setlocale(locale.LC_ALL, '')
except (locale.Error, IOError):
    pass
try:
    SYS_ENCODING = locale.getpreferredencoding()
except (locale.Error, IOError):
    pass
if not SYS_ENCODING or SYS_ENCODING in ('ANSI_X3.4-1968', 'US-ASCII', 'ASCII'):
    SYS_ENCODING = 'UTF-8'


class ekPy2:
    @staticmethod
    def fixStupidEncodings(x, silent=False):
        if type(x) == str:
            try:
                return x.decode(SYS_ENCODING)
            except UnicodeDecodeError:
                return None
        elif type(x) == unicode:
            return x
        else:
            return None

    @staticmethod
    def fixListEncodings(x):
        if type(x) != list and type(x) != tuple:
            return x
        else:
            return filter(lambda x: x != None, map(ek.fixStupidEncodings, x))

    @staticmethod
    def callPeopleStupid(x):
        try:
            return x.encode(SYS_ENCODING)
        except UnicodeEncodeError:
            return x.encode(SYS_ENCODING, 'ignore')

    @staticmethod
    def ek(func, *args, **kwargs):
        if os.name == 'nt':
            result = func(*args, **kwargs)
        else:
            result = func(*[ek.callPeopleStupid(x) if type(x) == str else x for x in args], **kwargs)

        if type(result) in (list, tuple):
            return ek.fixListEncodings(result)
        elif type(result) == str:
            return ek.fixStupidEncodings(result)
        else:
            return result


class ekPy3:
    @staticmethod
    def ek(func, *args, **kwargs):
        return func(*args, **kwargs)


if PY2:
    ek = ekPy2
else:
    ek = ekPy3


filename = env_var.get('NZBNP_FILENAME')
if re.search(r"\.tar\.gz$", filename, flags=re.I) is None:
    ext = os.path.splitext(filename)[1].lower()
else:
    ext = '.tar.gz'
cat = env_var.get('NZBNP_CATEGORY')
dir = env_var.get('NZBNP_DIRECTORY')
prio = env_var.get('NZBNP_PRIORITY')
top = env_var.get('NZBNP_TOP')
pause = env_var.get('NZBNP_PAUSED')
password = env_var.get('NZBPR_*Unpack:Password')
if 'NZBNP_DUPEKEY' in os.environ:
    dupekey = env_var.get('NZBNP_DUPEKEY')
    dupescore = env_var.get('NZBNP_DUPESCORE')
    dupemode = env_var.get('NZBNP_DUPEMODE')
else:
    dupekey = None
    dupescore = None
    dupemode = None

tmp_zipinfo = os.path.join(os.environ.get('NZBOP_TEMPDIR'), r'nzbget\unzip_scan\info')
nzb_list = []

def read_gzip_info(gzipfile):
    gf = gzipfile.fileobj
    pos = gf.tell()

    # Read archive size
    gf.seek(-4, 2)
    size = struct.unpack('<I', gf.read())[0]

    gf.seek(0)
    magic = gf.read(2)
    if magic != '\037\213':
        raise IOError('Not a gzipped file')

    method, flag, mtime = struct.unpack("<BBIxx", gf.read(8))

    if not flag & FNAME:
        # Not stored in the header, use the filename sans .gz
        gf.seek(pos)
        fname = gzipfile.name
        if fname.endswith('.gz'):
            fname = unquote(fname[:-3])
        return fname, size

    if flag & FEXTRA:
        # Read & discard the extra field, if present
        gf.read(struct.unpack("<H", gf.read(2)))

    # Read a null-terminated string containing the filename
    fname = []
    while True:
        s = gf.read(1)
        if not s or s=='\000':
            break
        fname.append(s)

    gf.seek(pos)
    return ''.join(fname), size

def save_obj(obj, name):
    tp = os.path.dirname(name)
    if not os.path.exists(tp):
        try:
            os.makedirs(tp)
        except:
            print("Error creating Dir %s" % tp)
            return
    try:
        with open(name, 'wb') as f:
            pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)
    except:
        print("Error saving: %s" % name)

def load_obj(name):
    if os.path.isfile(name):
        try:
            with open(name, 'rb') as f:
                return pickle.load(f)
        except:
            print("Error loading %s" % name)
            return None
    else:
        return None

def save_nzb_list():
    if nzb_list:
        save_obj(nzb_list, tmp_zipinfo)
    else:
        if os.path.isfile(tmp_zipinfo):
            try:
                os.unlink(tmp_zipinfo)
            except:
                print("Error deleting %s" % tmp_zipinfo)

def upgrade_nzb_list_9():
    global nzb_list
    nzb_list = [[el[0], el[1], el[2], el[3], el[4], password, el[5], el[6], el[7], el[8]] for el in nzb_list]

def load_nzb_list():
    global nzb_list
    nzb_list = load_obj(tmp_zipinfo)
    if nzb_list:
        if 9 == len(nzb_list[0]):
            upgrade_nzb_list_9()
        now = datetime.datetime.now()
        o_l = len(nzb_list)
        nzb_list[:] = [el for el in nzb_list if (now - el[9]).days < 1]
        if nzb_list is not None and o_l != len(nzb_list):
            save_nzb_list()

def get_files(zf):
    zi = zf.infolist()
    zi[:] = [el for el in zi if os.path.splitext(el.filename)[1].lower() == '.nzb']
    return zi

def get_tar_files(tf):
    ti = tf.getmembers()
    ti[:] = [el for el in ti if el.isfile() and os.path.splitext(el.name)[1].lower() == '.nzb']
    return ti

def get_rar_files(rf):
    ri = rf.infolist()
    ri[:] = [el for el in ri if os.path.splitext(el.filename)[1].lower() == '.nzb']
    return ri

def get_7z_files(z7f):
    z7i = z7f.getnames()
    z7i[:] = [el for el in z7i if os.path.splitext(el)[1].lower() == '.nzb']
    return z7i

def remove_filename():
    try:
        os.unlink(filename)
    except:
        print("Error deleting %s" % filename)


if not ek.ek(os.path.isfile, filename):
    sys.exit(0)

elif ext == '.zip':
    load_nzb_list()
    zipf = zipfile.ZipFile(filename, mode='r')
    zf = get_files(zipf)
    if zf:
        ek.ek(zipf.extractall, path=dir, members=zf)
        now = datetime.datetime.now()
        for z in zf:
            if nzb_list:
                nzb_list.append([z.filename, cat, prio, top, pause, password, dupekey, dupescore, dupemode, now])
            else:
                nzb_list = [[z.filename, cat, prio, top, pause, password, dupekey, dupescore, dupemode, now]]
        save_nzb_list()
    zipf.close()

    remove_filename()

elif ext == '.7z':
    load_nzb_list()
    sevenzf = py7zr.SevenZipFile(filename, mode='r')
    _7zf = get_7z_files(sevenzf)
    if _7zf:
        ek.ek(sevenzf.extractall, path=dir)
        now = datetime.datetime.now()
        for _7z in _7zf:
            if nzb_list:
                nzb_list.append([_7z, cat, prio, top, pause, password, dupekey, dupescore, dupemode, now])
            else:
                nzb_list = [[_7z, cat, prio, top, pause, password, dupekey, dupescore, dupemode, now]]
        save_nzb_list()
    sevenzf.close()

    remove_filename()

elif ext in ['.tar.gz', '.tar', '.tgz']:
    load_nzb_list()
    tarf = tarfile.open(filename, mode='r')
    tf = get_tar_files(tarf)
    if tf:
        ek.ek(tarf.extractall, path=dir, members=tf)
        now = datetime.datetime.now()
        for z in tf:
            if nzb_list:
                nzb_list.append([z.name, cat, prio, top, pause, password, dupekey, dupescore, dupemode, now])
            else:
                nzb_list = [[z.name, cat, prio, top, pause, password, dupekey, dupescore, dupemode, now]]
        save_nzb_list()
    tarf.close()

    remove_filename()

elif ext == '.gz':
    load_nzb_list()
    gzf =gzip.open(filename, mode='rb')
    out_filename, size = read_gzip_info(gzf)
    if out_filename and os.path.splitext(out_filename)[1].lower() == '.nzb':
        with open(os.path.join(os.path.dirname(filename), out_filename), 'wb') as outf:
            outf.write(gzf.read())
            outf.close()

        if gzf and out_filename:
            now = datetime.datetime.now()
            if nzb_list:
                nzb_list.append([os.path.basename(out_filename), cat, prio, top, pause, password, dupekey, dupescore, dupemode, now])
            else:
                nzb_list = [[os.path.basename(out_filename), cat, prio, top, pause, password, dupekey, dupescore, dupemode, now]]
            save_nzb_list()
    gzf.close()

    remove_filename()

elif ext == '.rar':
    load_nzb_list()
    rarf = rarfile.RarFile(filename, mode='r')
    rf = get_files(rarf)
    if rf:
        ek.ek(rarf.extractall, path=dir, members=rf)
        now = datetime.datetime.now()
        for r in rf:
            if nzb_list:
                nzb_list.append([r.filename, cat, prio, top, pause, password, dupekey, dupescore, dupemode, now])
            else:
                nzb_list = [[r.filename, cat, prio, top, pause, password, dupekey, dupescore, dupemode, now]]
        save_nzb_list()
    rarf.close()

    remove_filename()

elif ext == '.nzb' and os.path.exists(tmp_zipinfo):
    load_nzb_list()
    if nzb_list:
        ni = None
        f_l = os.path.basename(filename).lower()
        for i, nf in enumerate(nzb_list):
            if os.path.basename(nf[0]).lower() == f_l:
                ni = i
                break
        if ni is not None:
            print("[NZB] CATEGORY=%s" % nzb_list[ni][1])
            print("[NZB] PRIORITY=%s" % nzb_list[ni][2])
            print("[NZB] TOP=%s" % nzb_list[ni][3])
            print("[NZB] PAUSED=%s" % nzb_list[ni][4])
            print("[NZB] NZBPR_*Unpack:Password=%s" % nzb_list[ni][5])
            if dupekey is not None:
                print("[NZB] DUPEKEY=%s" % nzb_list[ni][6])
                print("[NZB] DUPESCORE=%s" % nzb_list[ni][7])
                print("[NZB] DUPEMODE=%s" % nzb_list[ni][8])
            del nzb_list[ni]
            save_nzb_list()
