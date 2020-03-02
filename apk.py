#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import call, PIPE, Popen
import re
from collections import OrderedDict
from pexpect import spawn, EOF, TIMEOUT

def re_compile(p):
    return re.compile(p, flags=re.MULTILINE)

class APKHandler:
    
    ## Config values
    TIMEOUT = None # Should be reasonably high (or None) as large packages can take a while to install
    
    ## Tuples of regex patterns, for use with pexpect

    # These are not compiled because we use them to build other patterns
    VERSION_BUILDER = r'(\d+[\d\-\.r]+)'
    PKG_BUILDER = r'(\w+(?:-\w+)*)-' + VERSION_BUILDER
    
    # Sudo-related responses
    SUDO_PASS_PROMPT = re_compile(r'^\[sudo\] password for (\w+): ')
    SUDO_TRY_AGAIN = re_compile(r'^Sorry, try again.\r\n')
    SUDO_FAIL = re_compile(r'^sudo: \d+ incorrect password attempts\r\n')
    NEWLINE = re_compile(r'^\r\n') # We get this after we provide password
    
    # APK-related responses
    ERROR = re_compile(r'^ERROR: (.+)\r\n')
    OK = re_compile(r'^OK: (.+)\r\n')
    PROGRESS = re_compile(r'^\((\d+)/(\d+)\) (.+)\r\n')
    EXEC = re_compile(r'^Executing ' + PKG_BUILDER + r'\.(.+)\r\n')
    FETCH_REPO = re_compile(r'^fetch (.+)\r\n')
    REPO_UPDATE_TIME = re_compile('^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.*\d*) \[(.+)\]\r\n')
    REPO_VERSION = re_compile(r'^(v\d{8}-\d{4}-\w{11}) \[(.+)\]\r\n')
    PACKAGE = re_compile('^' + PKG_BUILDER + r'\r\n')
    PKG_VERBOSE = re_compile('^' + PKG_BUILDER + r' - (.+)\r\n')
    PKG_DESC = re_compile('^' + PKG_BUILDER + r' description:\r\n')
    PKG_WEBPAGE = re_compile('^' + PKG_BUILDER + r' webpage:\r\n')
    PKG_SIZE = re_compile('^' + PKG_BUILDER + r' installed size:\r\n')
    CONFIG_GETTY = re_compile(r'^Configuring a getty on port (\w+) with baud rate (\d+)\r\n')
    
    # Other
    ANYTHING = r'(.+)\r\n'  # Should always be last
    
    # 'n' in the below comments represents the number of elements that have
    # been added to the "EXPECT" list prior to the relevant list
    
    APK_GENERIC = [
        ERROR,              # (n+)0: Generic error message
        OK                  # (n+)1: Command completed OK
    ]
    
    SUDO_GENERIC = [
        SUDO_PASS_PROMPT,   # (n+)0: sudo password prompt
        SUDO_TRY_AGAIN,     # (n+)1: sudo wrong password try again
        SUDO_FAIL,          # (n+)2: sudo wrong password too many times
        NEWLINE             # (n+)3: sudo sent a newline after we provided password
    ]
    
    # The below is used for add, del and upgrade because the range of
    # expected responses if largely the same (FETCH_REPO probably isn't
    # relevant to del, but including it is no harm and cuts down on code
    # repetition)
    ADD_DEL_UPGRADE_EXPECT = APK_GENERIC + SUDO_GENERIC + [
        PROGRESS,           # 6: Step message
        EXEC,               # 7: Executing a script after installation (trigger, post-install, etc)
        FETCH_REPO,         # 8: Fetching a repo
        CONFIG_GETTY,       # 9: Configuring a getty
        ANYTHING            # 10: Catch-all
    ]
    
    UPDATE_EXPECT = APK_GENERIC + SUDO_GENERIC + [
        FETCH_REPO,         # 6: Fetching a repo
        REPO_UPDATE_TIME,   # 7: Date and time of update
        REPO_VERSION        # 8: Repo version
    ]
    
    SEARCH_EXPECT = [
        PACKAGE             # 0: String consisting of package name + version
    ]
    
    SEARCH_VERBOSE_EXPECT = [
        PKG_VERBOSE         # 0: Verbose listing of package (name, version and description)
    ]
    
    PKG_INFO_EXPECT = [
        PKG_DESC,           # 0: Package description
        PKG_WEBPAGE,        # 1: Package website
        PKG_SIZE            # 2: Package installed size
    ]
    
    PEXPECT_ERRORS = [
        EOF,                # -2:   End of file (and no match found)
        TIMEOUT             # -1:   Process timed out
    ]
    
    
    def __init__(self, sudo_pass=None):
        self.sudo_pass = sudo_pass
    
    def apk(self, args, expects, handler, with_sudo=False):
        self._output = []
        if with_sudo:
            cmd = 'sudo'
            args.insert(0, 'apk')
        else:
            cmd = 'apk'
        proc = spawn(cmd, args, timeout=self.TIMEOUT, encoding='utf-8')#, maxread=1)
        #expects.append(re.compile(r'^(\w+)', flags=re.MULTILINE)) # Testing
        while True:
            try:
                #print('expecting')
                i = proc.expect(expects)
                if proc.match:
                    self._output.append(proc.match.string)
                #print('found', i)
                yield handler(i, proc)
            except (EOF, TIMEOUT):
                return self.output
    
    @property
    def output(self):
        return ''.join(self._output).split('\r\n')

    def add_del_upgrade(self, cmd, *other_args, packages=None):
        if cmd == 'add' or cmd == 'del':
            try:
                args = [cmd] + list(other_args) + packages
            except TypeError:
                # packages is probably string
                args = [cmd, '--no-progress'] + list(other_args)
                args.append(packages)
        elif cmd == 'upgrade':
            args = [cmd, '--no-progress'] + list(other_args)
        else:
            raise ValueError(f'Bad value for cmd: {cmd}')
        return self.apk(args, self.ADD_DEL_UPGRADE_EXPECT,
            self.add_del_upgrade_handler, with_sudo=True)
    
    def add(self, packages):
        return self.add_del_upgrade('add', packages=packages)
    
    def remove(self, packages, depends=False):
        if depends:
            return self.add_del_upgrade('del', '-r', packages=packages)
        else:
            return self.add_del_upgrade('del', packages=packages)
    
    def upgrade(self):
        return self.add_del_upgrade('upgrade')
    
    def add_del_upgrade_handler(self, i, proc):
        groups = proc.match.groups()
        print(groups)
        print(i)
        # TODO: Handle "generic" handlers (ie, sudo and apk) in separate
        # functions
        response = self.apk_handler(i, proc, 0)
        if response:
            return response
        response = self.sudo_handler(i, proc, 2)
        if response:
            return response
        response = {}
        if i == 6:
            # We have received a message indicating that an intermediate
            # step in an install / uninstall has occurred
            step_num, num_steps, msg = groups
            response['type'] = 'PROGRESS'
            response['step'] = int(step_num)
            response['total_steps'] = int(num_steps)
            response['percent'] = (int(step_num)/int(num_steps)) * 100
            response['description'] = f'Step {step_num} of {num_steps}'
            response['message'] = msg
        elif i == 7:
            # A post-install (or possibly post-uninstall) trigger has
            # been executed.
            pkg, version, exec_type = groups
            response['type'] = 'EXEC'
            response['package'] = pkg
            response['version'] = version
            response['description'] = f'Executing {pkg}-{version}.{exec_type}'
        elif i == 8:
            # Fetching an up-to-date repository.
            repo, = groups
            response['type'] = 'FETCH'
            response['repo'] = repo
            response['description'] = f'Fetching repository {repo}'
        elif i == 9:
            # Configuring a new TTY.
            port, baud_rate = groups
            response['type'] = 'GETTY'
            response['port'] = port
            response['baud_rate'] = int(baud_rate)
            response['description'] = f'Configuring getty on port {port} with baud rate {baud_rate}'
        elif i == 10:
            # Some other message.
            msg, = groups
            response['type'] = 'OTHER'
            response['message'] = msg
            response['description'] = 'Got an unexpected response'
        
        return response
    
    def search(self, query=None, verbose=False):
        args = ['search']
        if verbose:
            args.append('--verbose')
            expects = self.SEARCH_VERBOSE_EXPECT
        else:
            expects = self.SEARCH_EXPECT
        if query:
            args += query.split(' ')
        return self.apk(args, expects, self.search_handler)
    
    def get_installed(self):
        return self.apk(['info', '--verbose'], self.SEARCH_EXPECT, self.search_handler)
    
    def search_handler(self, i, proc):
        # apk search (with or without other args) and apk info (without args"
        # both use this handler.  apk info (with other args) does not.
        groups = proc.match.groups()
        response = {'type': 'RESULT'}
        if len(groups) == 2:
            # Non-verbose (name and version only)
            name, version = groups
            response['package'] = name
            response['version'] = version
        elif len(groups) == 3:
            name, version, desc = groups
            response['package'] = name
            response['version'] = version
            response['description'] = desc
        return response
    
    def update(self):
        return self.apk(['update'], self.UPDATE_EXPECT, self.update_handler, with_sudo=True)
    
    def update_handler(self, i, proc):
        groups = proc.match.groups()
        response = self.apk_handler(i, proc, 0)
        if response:
            return response
        response = self.sudo_handler(i, proc, 2)
        if response:
            return response
        response = {}
        if i == 6:
            url, = groups
            response['type'] = 'FETCH'
            response['url'] = url
            response['description'] = f'Fetched URL {url}'
        elif i == 7:
            time, url = groups
            response['type'] = 'UPDATE_TIME'
            response['time'] = time
            response['url'] = url
        elif i == 8:
            version, url = groups
            response['type'] = 'UPDATE_VERSION'
            response['version'] = version
            response['url'] = url
            response['description'] = f'Got updated repo version {version} from {url}'
        return response

    def apk_handler(self, i, proc, n):
        response = {}
        groups = proc.match.groups()
        if i == n:
            # ERROR
            msg, = groups
            response['type'] = 'ERROR'
            response['message'] = msg
            response['description'] = 'Command failed'
        elif i == n+1:
            # OK
            msg, = groups
            response['type'] = 'OK'
            response['message'] = msg
            response['description'] = 'Command completed successfully'
        return response
    
    def sudo_handler(self, i, proc, n):
        response = {}
        if i == n:
            # Being asked for sudo password
            proc.send(self.sudo_pass + '\n')
            response['type'] = 'PROMPT'
            response['description'] = 'Asked for sudo password'
        elif i == n+1:
            # Being asked again for sudo password
            proc.send(self.sudo_pass + '\n')
            response['type'] = 'PROMPT'
            response['description'] = 'Asked for sudo password'
        elif i == n+2:
            # Failed because sudo password is wrong
            response['type'] = 'ERROR'
            response['description'] = 'Failed because sudo password is wrong'
        elif i == n+3:
            # We received a newline, probably from sudo after providing our password
            response['type'] = 'NEWLINE'
            response['description'] = 'Received a newline on its own'
        return response

def test(h, fn, *args, **kwargs):
    r = []
    for line in fn(*args, **kwargs):
        r.append(line)
        print(line)
    return r, h.output

def update():
    h = APKHandler('1234')
    return test(h, h.update)

def add(*packages):
    h = APKHandler('1234')
    return test(h, h.add, *packages)

def remove(*packages):
    h = APKHandler('1234')
    return test(h, h.remove, *packages)

def upgrade():
    h = APKHandler('1234')
    return test(h, h.upgrade)

def search(query):
    h = APKHandler('1234')
    return test(h, h.search, query)

def get_installed():
    h = APKHandler('1234')
    return test(h, h.get_installed)
