#!/usr/bin/env python3
#
# unt-scan.py - 2018-01-16 - Cris van Pelt <c.vanpelt@flusso.nl>
#
# Collects the UNT pickle database published by the Ubuntu Security Team
# and determines if anything needs to be upgraded.
#
# Everything is printed to stdout, making this script suitable for use
# in cron.
#
import pickle
import apt
import getopt
import apt_pkg
import sys
import os
import email
import tempfile
import time

# We're using our own minimal caching to keep dependencies to a
# minimum. Ideally this would just use Requests with a caching
# backend, but such is life.
#
# Python 3.2 (precise) does not do HEAD requests via urllib.request,
# so use http.client instead. :'(
#
# import urllib.request
import http.client

__version__ = '3.8rc4'

# These are the default values. Most can be overridden on the command line.
CONFIG = {
    'PERSISTENT_STORAGE': True,
    'DIRECTORY': '/var/lib/unt-scan',
    'ALERT_ONCE': True,
    'PICKLE_HOST': 'people.canonical.com',
    'PICKLE_URL': '/~ubuntu-security/usn/database.pickle',
    'HTTPS': True,
}

# ¯\_(ツ)_/¯
if sys.version_info[1] < 4:
    FileNotFoundError = IOError


class AlertRegistry():
    """
    Tracks for which UNTs alerts have already been printed.
    The state can easily be reset by removing the 'alerts.pickle' file.

    The registry file is just a pickled Python list object containing
    UNT identifiers as strings.
    """
    def __init__(self, storage_file='alerts.pickle'):
        self.storage_file = storage_file
        try:
            with open(storage_file, 'rb+') as f:
                self.registry = pickle.load(f)
        except FileNotFoundError:
            self.registry = []
            self.save()

    def register(self, unt):
        self.registry.append(unt)

    def is_registered(self, unt):
        return (unt in self.registry)

    def save(self):
        with open(self.storage_file, 'wb') as f:
            pickle.dump(self.registry, f)


def database_file():
    """
    Returns an open filehandle to the pickle database.
    If required, the database will be downloaded.
    """
    # These should probably just be function parameters with
    # appropriate command-line options.
    host = CONFIG['PICKLE_HOST']
    url = CONFIG['PICKLE_URL']
    if CONFIG['HTTPS']:
        HTTPConnection = http.client.HTTPSConnection
    else:
        HTTPConnection = http.client.HTTPConnection

    # Don't do any cache checks if we don't have a storage
    # directory configured. Just get the file.
    if not CONFIG['PERSISTENT_STORAGE']:
        connection = HTTPConnection(host, timeout=10)
        connection.request('GET', url)
        response = connection.getresponse()
        t = tempfile.TemporaryFile()
        t.write(response.read())
        t.seek(0, 0)
        return t

    # HEAD request; the ETag value is the primary source for caching,
    # falling back on Last-Modified.  That is probably not HTTP-compliant
    # but, like, whatevs.
    connection = HTTPConnection(host, timeout=10)
    response = connection.request('HEAD', url,
                                  headers={'User-Agent': 'unt-scan.py {}'.format(__version__)})
    response = connection.getresponse()
    connection.close()

    if response.status != 200:
        raise Exception('Unexpected response while doing HEAD request on {}'.format(url))

    # Tuples are annoying. Restructure to dict.
    headers_tuples = response.getheaders()
    headers = {}
    for item in headers_tuples:
        headers[item[0]] = item[1]

    # Just save the HTTP headers so we can check the previous run's ETag etc.
    try:
        f = open(os.path.join(CONFIG['DIRECTORY'], 'db.metadata.pickle'), 'rb+')
        old_headers = pickle.load(f)
        f.seek(0, 0)
    except FileNotFoundError:
        f = open(os.path.join(CONFIG['DIRECTORY'], 'db.metadata.pickle'), 'wb+')
        old_headers = {}

    pickle.dump(headers, f)
    f.close()

    update = True
    if 'ETag' in headers and 'ETag' in old_headers:
        if headers['ETag'] == old_headers['ETag']:
            update = False
    elif 'Last-Modified' in headers and 'Last-Modified' in old_headers:
        if old_headers['Last-Modified'] < headers['Last-Modified']:
            update = False

    # If we don't need to update, return the file-handle to the cached file.
    # If that fails for whatever reason, try to update anyway.
    if not update:
        try:
            response = open(os.path.join(CONFIG['DIRECTORY'], 'db.pickle'), 'rb')
        except Exception:
            update = True

    if update:
        connection = HTTPConnection(host, timeout=10)
        response = connection.request('GET', url,
                                      headers={'User-Agent': 'unt-scan.py {}'.format(__version__)})
        response = connection.getresponse()

        # This is more likely to raise one of the http.client exceptions, but just check
        # to be sure.
        if (not response) or (response.status != 200):
            raise Exception('Error retrieving pickle database: Got code {}'.
                            format(response.status))

        f = open(os.path.join(CONFIG['DIRECTORY'], 'db.pickle'), 'wb+')
        f.write(response.read())
        f.seek(0, 0)
        response = f

        connection.close()

    return response


def filter_db(db, release_codename):
    """
    This generator filters the provided pickle database by releasename and restructures"
    the input a little bit, to make it easier to parse.
    """
    for unt, content in db.items():
        if release_codename not in list(content['releases'].keys()):
            continue
        else:
            for package, contents in content['releases'][release_codename]['binaries'].items():
                # I don't even know what these are, but this seems to work.
                if 'isummary' in content:
                    summary = content['isummary']
                elif 'summary' in content:
                    summary = content['summary']
                else:
                    summary = 'No summary'

                yield {
                    'unt': unt,
                    'name': package,
                    'version': contents['version'],
                    'summary': summary,
                    'cves': content['cves'],
                }


def get_codename():
    with open('/etc/lsb-release', 'r') as f:
        for line in f.readlines():
            if line.startswith('DISTRIB_CODENAME='):
                return line.split('=')[1].rstrip()


def show_age():
    try:
        with open(os.path.join(CONFIG['DIRECTORY'], 'db.metadata.pickle'), 'rb') as f:
            headers = pickle.load(f)

        if 'Last-Modified' in headers:
            # Python 3.2 does not have parsedate_to_datetime
            age = email.utils.parsedate(headers['Last-Modified'])

            print('{:.0f}'.format(time.time() - time.mktime(age)))
    except Exception:
        print('0')


def show_help():
    print("unt-scan.py version {1}\n"
          "Usage: {0} [-ha] [-d DIRECTORY]\n"
          "\n"
          "    -h, --help                          Show this help text.\n"
          "    -a, --all                           Show alerts that have already been shown.\n"
          "    -c, --codename=CODENAME             Set the Ubuntu release codename (default: {3}).\n"
          "    -o, --once                          Show alerts only once (default).\n"
          "    -d, --directory=DIRECTORY           Store files in DIRECTORY (default: {2}).\n"
          "    -A, --age                           Shows the age of the database in seconds, or 0 if no cache.\n"
          .format(sys.argv[0], __version__, CONFIG['DIRECTORY'], get_codename()))


if __name__ == '__main__':
    issues_found = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hd:aoc:A",
                                   ["help", "directory=", "all", "once", "age"])
    except getopt.GetoptError as err:
        print(str(err))
        sys.exit(2)

    for o, a in opts:
        if o in ('-h', '--help'):
            show_help()
            sys.exit(0)
        elif o in ('-d', '--directory='):
            CONFIG['PERSISTENT_STORAGE'] = True
            CONFIG['DIRECTORY'] = a
        elif o in ('-a', '--all'):
            CONFIG['ALERT_ONCE'] = False
        elif o in ('-o', '--once'):
            CONFIG['ALERT_ONCE'] = True
        elif o in ('-c', '--codename='):
            codename = args
        elif o in ('-A', '--age'):
            show_age()
            sys.exit(0)

    if CONFIG['ALERT_ONCE'] and not CONFIG['PERSISTENT_STORAGE']:
        raise RuntimeError('Cannot track alerts without persistent storage.')

    if 'codename' not in vars():
        codename = get_codename()

    if not os.path.isdir(CONFIG['DIRECTORY']):
        if not os.path.exists(CONFIG['DIRECTORY']):
            os.makedirs(CONFIG['DIRECTORY'])
        else:
            raise Exception('{} exists, but is not a directory.'.format(CONFIG['DIRECTORY']))

    db_file = database_file()
    db = pickle.load(db_file, encoding='iso-8859-1')

    apt_pkg.init_system()
    cache = apt.Cache()

    registry = AlertRegistry(os.path.join(CONFIG['DIRECTORY'], 'alerts.pickle'))

    for package in filter_db(db, codename):
        if package['name'] in cache and cache[package['name']].is_installed:
            cached_package = cache[package['name']]
            if apt_pkg.version_compare(cached_package.installed.version, package['version']) < 0:
                if CONFIG['ALERT_ONCE']:
                    alert = not registry.is_registered(package['unt'])
                else:
                    alert = True

                if alert:
                    registry.register(package['unt'])
                    issues_found = True

                    print('UNT: {}\n   CVEs: {}'.format(package['unt'], ', '.join(package['cves'])))
                    print('   Package: {}\n   Installed version: {}\n   Fix Version: {}'.
                          format(package['name'], cached_package.installed.version, package['version']))
                    print('   Short Summary: {}'.format(package['summary']))

    registry.save()

    if issues_found:
        sys.exit(1)
