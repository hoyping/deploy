# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See LICENSE for more details.
#
# Copyright: Red Hat Inc. 2013-2014
# Author: Lucas Meneghel Rodrigues <lmr@redhat.com>

"""
Functions dedicated to find and run external commands.
"""

import logging
import os
import re
import signal
import time
import stat
import shlex
import shutil
import threading
import fnmatch

try:
    import subprocess32 as subprocess
    SUBPROCESS32_SUPPORT = True
except ImportError:
    import subprocess
    SUBPROCESS32_SUPPORT = False

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import runtime
import path

log = logging.getLogger('avocado.test')
stdout_log = logging.getLogger('avocado.test.stdout')
stderr_log = logging.getLogger('avocado.test.stderr')

#: The active wrapper utility script.
CURRENT_WRAPPER = None

#: The global wrapper.
#: If set, run every process under this wrapper.
WRAP_PROCESS = None

#: Set wrapper per program names.
#: A list of wrappers and program names.
#: Format: [ ('/path/to/wrapper.sh', 'progname'), ... ]
WRAP_PROCESS_NAMES_EXPR = []

#: Exception to be raised when users of this API need to know that the
#: execution of a given process resulted in undefined behavior. One
#: concrete example when a user, in an interactive session, let the
#: inferior process exit before before avocado resumed the debugger
#: session. Since the information is unknown, and the behavior is
#: undefined, this situation will be flagged by an exception.
UNDEFINED_BEHAVIOR_EXCEPTION = None


# variable=value bash assignment
_RE_BASH_SET_VARIABLE = re.compile(r"[a-zA-Z]\w*=.*")


class CmdError(Exception):

    def __init__(self, command=None, result=None, additional_text=None):
        self.command = command
        self.result = result
        self.additional_text = additional_text

    def __str__(self):
        if self.result is not None:
            if self.result.interrupted:
                return "Command %s interrupted by user (Ctrl+C)" % self.command
            if self.result.exit_status is None:
                msg = "Command '%s' failed and is not responding to signals"
                msg %= self.command
            else:
                msg = "Command '%s' failed (rc=%d)"
                msg %= (self.command, self.result.exit_status)
            if self.additional_text:
                msg += ", " + self.additional_text
            return msg
        else:
            return "CmdError"


def pid_exists(pid):
    """
    Return True if a given PID exists.

    :param pid: Process ID number.
    """
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def safe_kill(pid, signal):
    """
    Attempt to send a signal to a given process that may or may not exist.

    :param signal: Signal number.
    """
    try:
        os.kill(pid, signal)
        return True
    except Exception:
        return False


def kill_process_tree(pid, sig=signal.SIGKILL, send_sigcont=True):
    """
    Signal a process and all of its children.

    If the process does not exist -- return.

    :param pid: The pid of the process to signal.
    :param sig: The signal to send to the processes.
    """
    if not safe_kill(pid, signal.SIGSTOP):
        return
    children = system_output("ps --ppid=%d -o pid=" % pid, ignore_status=True,
                             verbose=False).split()
    for child in children:
        kill_process_tree(int(child), sig)
    safe_kill(pid, sig)
    if send_sigcont:
        safe_kill(pid, signal.SIGCONT)


def kill_process_by_pattern(pattern):
    """
    Send SIGTERM signal to a process with matched pattern.

    :param pattern: normally only matched against the process name
    """
    cmd = "pkill -f %s" % pattern
    result = run(cmd, ignore_status=True)
    if result.exit_status:
        logging.error("Failed to run '%s': %s", cmd, result)
    else:
        logging.info("Succeed to run '%s'.", cmd)


def process_in_ptree_is_defunct(ppid):
    """
    Verify if any processes deriving from PPID are in the defunct state.

    Attempt to verify if parent process and any children from PPID is defunct
    (zombie) or not.

    :param ppid: The parent PID of the process to verify.
    """
    defunct = False
    try:
        pids = get_children_pids(ppid)
    except CmdError:  # Process doesn't exist
        return True
    for pid in pids:
        cmd = "ps --no-headers -o cmd %d" % int(pid)
        proc_name = system_output(cmd, ignore_status=True, verbose=False)
        if '<defunct>' in proc_name:
            defunct = True
            break
    return defunct


def get_children_pids(ppid):
    """
    Get all PIDs of children/threads of parent ppid
    param ppid: parent PID
    return: list of PIDs of all children/threads of ppid
    """
    return system_output("ps -L --ppid=%d -o lwp" % ppid, verbose=False).split('\n')[1:]


def binary_from_shell_cmd(cmd):
    """
    Tries to find the first binary path from a simple shell-like command.

    :note: It's a naive implementation, but for commands like:
           `VAR=VAL binary -args || true` gives the right resutl (binary)
    :param cmd: simple shell-like binary
    :return: first found binary from the cmd
    """
    try:
        cmds = shlex.split(cmd)
    except ValueError:
        log.warning("binary_from_shell_cmd: Shlex split of %s failed, using "
                    "using simple split.", cmd)
        cmds = cmd.split(" ")
    for item in cmds:
        if not _RE_BASH_SET_VARIABLE.match(item):
            return item
    raise ValueError("Unable to parse first binary from '%s'" % cmd)


class CmdResult(object):

    """
    Command execution result.

    :param command: String containing the command line itself
    :param exit_status: Integer exit code of the process
    :param stdout: String containing stdout of the process
    :param stderr: String containing stderr of the process
    :param duration: Elapsed wall clock time running the process
    """

    def __init__(self, command="", stdout="", stderr="",
                 exit_status=None, duration=0):
        self.command = command
        self.exit_status = exit_status
        self.stdout = stdout
        self.stderr = stderr
        self.duration = duration
        self.interrupted = False

    def __repr__(self):
        cmd_rep = ("Command: %s\n"
                   "Exit status: %s\n"
                   "Duration: %s\n"
                   "Stdout:\n%s\n"
                   "Stderr:\n%s\n" % (self.command, self.exit_status,
                                      self.duration, self.stdout, self.stderr))
        if self.interrupted:
            cmd_rep += "Command interrupted by user (Ctrl+C)\n"
        return cmd_rep


class SubProcess(object):

    """
    Run a subprocess in the background, collecting stdout/stderr streams.
    """

    def __init__(self, cmd, verbose=True, allow_output_check='all',
                 shell=False, env=None, sudo=False):
        """
        Creates the subprocess object, stdout/err, reader threads and locks.

        :param cmd: Command line to run.
        :type cmd: str
        :param verbose: Whether to log the command run and stdout/stderr.
        :type verbose: bool
        :param allow_output_check: Whether to log the command stream outputs
                                   (stdout and stderr) in the test stream
                                   files. Valid values: 'stdout', for
                                   allowing only standard output, 'stderr',
                                   to allow only standard error, 'all',
                                   to allow both standard output and error
                                   (default), and 'none', to allow
                                   none to be recorded.
        :type allow_output_check: str
        :param shell: Whether to run the subprocess in a subshell.
        :type shell: bool
        :param env: Use extra environment variables.
        :type env: dict
        :param sudo: Whether the command requires admin privileges to run,
                     so that sudo will be prepended to the command.
                     The assumption here is that the user running the command
                     has a sudo configuration such that a password won't be
                     prompted. If that's not the case, the command will
                     straight out fail.
        """
        # Now assemble the final command considering the need for sudo
        self.cmd = self._prepend_sudo(cmd, sudo, shell)
        self.verbose = verbose
        self.allow_output_check = allow_output_check
        self.result = CmdResult(self.cmd)
        self.shell = shell
        if env:
            self.env = os.environ.copy()
            self.env.update(env)
        else:
            self.env = None
        self._popen = None

    def __repr__(self):
        if self._popen is None:
            rc = '(not started)'
        elif self.result.exit_status is None:
            rc = '(running)'
        else:
            rc = self.result.exit_status
        return '%s(cmd=%r, rc=%r)' % (self.__class__.__name__, self.cmd, rc)

    def __str__(self):
        if self._popen is None:
            rc = '(not started)'
        elif self.result.exit_status is None:
            rc = '(running)'
        else:
            rc = '(finished with exit status=%d)' % self.result.exit_status
        return '%s %s' % (self.cmd, rc)

    @staticmethod
    def _prepend_sudo(cmd, sudo, shell):
        if sudo and os.getuid() != 0:
            try:
                sudo_cmd = '%s -n' % path.find_command('sudo')
            except path.CmdNotFoundError as details:
                log.error(details)
                log.error('Parameter sudo=True provided, but sudo was '
                          'not found. Please consider adding sudo to '
                          'your OS image')
                return cmd
            if shell:
                if ' -s' not in sudo_cmd:
                    sudo_cmd = '%s -s' % sudo_cmd
            cmd = '%s %s' % (sudo_cmd, cmd)
        return cmd

    def _init_subprocess(self):
        if self._popen is None:
            if self.verbose:
                log.info("Running '%s'", self.cmd)
            if self.shell is False:
                cmd = shlex.split(self.cmd)
            else:
                cmd = self.cmd
            try:
                self._popen = subprocess.Popen(cmd,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE,
                                               shell=self.shell,
                                               env=self.env)
            except OSError as details:
                if details.errno == 2:
                    exc = OSError("File '%s' not found" % self.cmd.split()[0])
                    exc.errno = 2
                    raise exc
                else:
                    raise

            self.start_time = time.time()
            self.stdout_file = StringIO()
            self.stderr_file = StringIO()
            self.stdout_lock = threading.Lock()
            self.stdout_thread = threading.Thread(target=self._fd_drainer,
                                                  name="%s-stdout" % self.cmd,
                                                  args=[self._popen.stdout])
            self.stdout_thread.daemon = True
            self.stderr_lock = threading.Lock()
            self.stderr_thread = threading.Thread(target=self._fd_drainer,
                                                  name="%s-stderr" % self.cmd,
                                                  args=[self._popen.stderr])
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            def signal_handler(signum, frame):
                self.result.interrupted = True
                self.wait()
            try:
                signal.signal(signal.SIGINT, signal_handler)
            except ValueError:
                if self.verbose:
                    log.info("Command %s running on a thread", self.cmd)

    def _fd_drainer(self, input_pipe):
        """
        Read from input_pipe, storing and logging output.

        :param input_pipe: File like object to the stream.
        """
        stream_prefix = "%s"
        if input_pipe == self._popen.stdout:
            prefix = '[stdout] %s'
            if self.allow_output_check in ['none', 'stderr']:
                stream_logger = None
            else:
                stream_logger = stdout_log
            output_file = self.stdout_file
            lock = self.stdout_lock
        elif input_pipe == self._popen.stderr:
            prefix = '[stderr] %s'
            if self.allow_output_check in ['none', 'stdout']:
                stream_logger = None
            else:
                stream_logger = stderr_log
            output_file = self.stderr_file
            lock = self.stderr_lock

        fileno = input_pipe.fileno()

        bfr = ''
        while True:
            tmp = os.read(fileno, 1024)
            if tmp == '':
                if self.verbose and bfr:
                    for line in bfr.splitlines():
                        log.debug(prefix, line)
                        if stream_logger is not None:
                            stream_logger.debug(stream_prefix, line)
                break
            lock.acquire()
            try:
                output_file.write(tmp)
                if self.verbose:
                    bfr += tmp
                    if tmp.endswith('\n'):
                        for line in bfr.splitlines():
                            log.debug(prefix, line)
                            if stream_logger is not None:
                                stream_logger.debug(stream_prefix, line)
                        bfr = ''
            finally:
                lock.release()

    def _fill_results(self, rc):
        self._init_subprocess()
        self.result.exit_status = rc
        if self.result.duration == 0:
            self.result.duration = time.time() - self.start_time
        self._fill_streams()

    def _fill_streams(self):
        """
        Close subprocess stdout and stderr, and put values into result obj.
        """
        # Cleaning up threads
        self.stdout_thread.join()
        self.stderr_thread.join()
        # Clean subprocess pipes and populate stdout/err
        self._popen.stdout.close()
        self._popen.stderr.close()
        self.result.stdout = self.get_stdout()
        self.result.stderr = self.get_stderr()

    def start(self):
        """
        Start running the subprocess.

        This method is particularly useful for background processes, since
        you can start the subprocess and not block your test flow.

        :return: Subprocess PID.
        :rtype: int
        """
        self._init_subprocess()
        return self._popen.pid

    def get_stdout(self):
        """
        Get the full stdout of the subprocess so far.

        :return: Standard output of the process.
        :rtype: str
        """
        self._init_subprocess()
        self.stdout_lock.acquire()
        stdout = self.stdout_file.getvalue()
        self.stdout_lock.release()
        return stdout

    def get_stderr(self):
        """
        Get the full stderr of the subprocess so far.

        :return: Standard error of the process.
        :rtype: str
        """
        self._init_subprocess()
        self.stderr_lock.acquire()
        stderr = self.stderr_file.getvalue()
        self.stderr_lock.release()
        return stderr

    def terminate(self):
        """
        Send a :attr:`signal.SIGTERM` to the process.
        """
        self._init_subprocess()
        self.send_signal(signal.SIGTERM)

    def kill(self):
        """
        Send a :attr:`signal.SIGKILL` to the process.
        """
        self._init_subprocess()
        self.send_signal(signal.SIGKILL)

    def send_signal(self, sig):
        """
        Send the specified signal to the process.

        :param sig: Signal to send.
        """
        self._init_subprocess()
        self._popen.send_signal(sig)

    def poll(self):
        """
        Call the subprocess poll() method, fill results if rc is not None.
        """
        self._init_subprocess()
        rc = self._popen.poll()
        if rc is not None:
            self._fill_results(rc)
        return rc

    def wait(self):
        """
        Call the subprocess poll() method, fill results if rc is not None.
        """
        self._init_subprocess()
        rc = self._popen.wait()
        if rc is not None:
            self._fill_results(rc)
        return rc

    def stop(self):
        """
        Stop background subprocess.

        Call this method to terminate the background subprocess and
        wait for it results.
        """
        self._init_subprocess()
        if self.result.exit_status is None:
            self.terminate()
        return self.wait()

    def run(self, timeout=None, sig=signal.SIGTERM):
        """
        Start a process and wait for it to end, returning the result attr.

        If the process was already started using .start(), this will simply
        wait for it to end.

        :param timeout: Time (seconds) we'll wait until the process is
                        finished. If it's not, we'll try to terminate it
                        and get a status.
        :type timeout: float
        :param sig: Signal to send to the process in case it did not end after
                    the specified timeout.
        :type sig: int
        :returns: The command result object.
        :rtype: A :class:`CmdResult` instance.
        """
        self._init_subprocess()
        start_time = time.time()

        if timeout is None:
            self.wait()

        if timeout > 0.0:
            while time.time() - start_time < timeout:
                self.poll()
                if self.result.exit_status is not None:
                    break

        if self.result.exit_status is None:
            internal_timeout = 1.0
            self.send_signal(sig)
            stop_time = time.time() + internal_timeout
            while time.time() < stop_time:
                self.poll()
                if self.result.exit_status is not None:
                    break
            else:
                self.kill()
                self.poll()

        # If all this work fails, we're dealing with a zombie process.
        e_msg = 'Zombie Process %s' % self._popen.pid
        assert self.result.exit_status is not None, e_msg

        return self.result


class WrapSubProcess(SubProcess):

    """
    Wrap subprocess inside an utility program.
    """

    def __init__(self, cmd, verbose=True, allow_output_check='all',
                 shell=False, env=None, wrapper=None, sudo=False):
        if wrapper is None and CURRENT_WRAPPER is not None:
            wrapper = CURRENT_WRAPPER
        self.wrapper = wrapper
        if self.wrapper:
            if not os.path.exists(self.wrapper):
                raise IOError("No such wrapper: '%s'" % self.wrapper)
            cmd = wrapper + ' ' + cmd
        super(WrapSubProcess, self).__init__(cmd, verbose, allow_output_check,
                                             shell, env, sudo)


def should_run_inside_wrapper(cmd):
    """
    Wether the given command should be run inside the wrapper utility.

    :param cmd: the command arguments, from where we extract the binary name
    """
    global CURRENT_WRAPPER
    CURRENT_WRAPPER = None
    args = shlex.split(cmd)
    cmd_binary_name = args[0]

    for script, cmd_expr in WRAP_PROCESS_NAMES_EXPR:
        if fnmatch.fnmatch(cmd_binary_name, cmd_expr):
            CURRENT_WRAPPER = script

    if WRAP_PROCESS is not None and CURRENT_WRAPPER is None:
        CURRENT_WRAPPER = WRAP_PROCESS

    if CURRENT_WRAPPER is None:
        return False
    else:
        return True


def run(cmd, timeout=None, verbose=True, ignore_status=False,
        allow_output_check='all', shell=False, env=None, sudo=False):
    """
    Run a subprocess, returning a CmdResult object.

    :param cmd: Command line to run.
    :type cmd: str
    :param timeout: Time limit in seconds before attempting to kill the
                    running process. This function will take a few seconds
                    longer than 'timeout' to complete if it has to kill the
                    process.
    :type timeout: float
    :param verbose: Whether to log the command run and stdout/stderr.
    :type verbose: bool
    :param ignore_status: Whether to raise an exception when command returns
                          =! 0 (False), or not (True).
    :type ignore_status: bool
    :param allow_output_check: Whether to log the command stream outputs
                               (stdout and stderr) in the test stream
                               files. Valid values: 'stdout', for
                               allowing only standard output, 'stderr',
                               to allow only standard error, 'all',
                               to allow both standard output and error
                               (default), and 'none', to allow
                               none to be recorded.
    :type allow_output_check: str
    :param shell: Whether to run the command on a subshell
    :type shell: bool
    :param env: Use extra environment variables
    :type env: dict
    :param sudo: Whether the command requires admin privileges to run,
                 so that sudo will be prepended to the command.
                 The assumption here is that the user running the command
                 has a sudo configuration such that a password won't be
                 prompted. If that's not the case, the command will
                 straight out fail.

    :return: An :class:`CmdResult` object.
    :raise: :class:`CmdError`, if ``ignore_status=False``.
    """
    klass = get_sub_process_klass(cmd)
    sp = klass(cmd=cmd, verbose=verbose,
               allow_output_check=allow_output_check, shell=shell, env=env,
               sudo=sudo)
    cmd_result = sp.run(timeout=timeout)
    fail_condition = cmd_result.exit_status != 0 or cmd_result.interrupted
    if fail_condition and not ignore_status:
        raise CmdError(cmd, sp.result)
    return cmd_result


def system(cmd, timeout=None, verbose=True, ignore_status=False,
           allow_output_check='all', shell=False, env=None, sudo=False):
    """
    Run a subprocess, returning its exit code.

    :param cmd: Command line to run.
    :type cmd: str
    :param timeout: Time limit in seconds before attempting to kill the
                    running process. This function will take a few seconds
                    longer than 'timeout' to complete if it has to kill the
                    process.
    :type timeout: float
    :param verbose: Whether to log the command run and stdout/stderr.
    :type verbose: bool
    :param ignore_status: Whether to raise an exception when command returns
                          =! 0 (False), or not (True).
    :type ignore_status: bool
    :param allow_output_check: Whether to log the command stream outputs
                               (stdout and stderr) in the test stream
                               files. Valid values: 'stdout', for
                               allowing only standard output, 'stderr',
                               to allow only standard error, 'all',
                               to allow both standard output and error
                               (default), and 'none', to allow
                               none to be recorded.
    :type allow_output_check: str
    :param shell: Whether to run the command on a subshell
    :type shell: bool
    :param env: Use extra environment variables.
    :type env: dict
    :param sudo: Whether the command requires admin privileges to run,
                 so that sudo will be prepended to the command.
                 The assumption here is that the user running the command
                 has a sudo configuration such that a password won't be
                 prompted. If that's not the case, the command will
                 straight out fail.

    :return: Exit code.
    :rtype: int
    :raise: :class:`CmdError`, if ``ignore_status=False``.
    """
    cmd_result = run(cmd=cmd, timeout=timeout, verbose=verbose, ignore_status=ignore_status,
                     allow_output_check=allow_output_check, shell=shell, env=env,
                     sudo=sudo)
    return cmd_result.exit_status


def system_output(cmd, timeout=None, verbose=True, ignore_status=False,
                  allow_output_check='all', shell=False, env=None, sudo=False):
    """
    Run a subprocess, returning its output.

    :param cmd: Command line to run.
    :type cmd: str
    :param timeout: Time limit in seconds before attempting to kill the
                    running process. This function will take a few seconds
                    longer than 'timeout' to complete if it has to kill the
                    process.
    :type timeout: float
    :param verbose: Whether to log the command run and stdout/stderr.
    :type verbose: bool
    :param ignore_status: Whether to raise an exception when command returns
                          =! 0 (False), or not (True).
    :param allow_output_check: Whether to log the command stream outputs
                               (stdout and stderr) in the test stream
                               files. Valid values: 'stdout', for
                               allowing only standard output, 'stderr',
                               to allow only standard error, 'all',
                               to allow both standard output and error
                               (default), and 'none', to allow
                               none to be recorded.
    :type allow_output_check: str
    :param shell: Whether to run the command on a subshell
    :type shell: bool
    :param env: Use extra environment variables
    :type env: dict
    :param sudo: Whether the command requires admin privileges to run,
                 so that sudo will be prepended to the command.
                 The assumption here is that the user running the command
                 has a sudo configuration such that a password won't be
                 prompted. If that's not the case, the command will
                 straight out fail.

    :return: Command output.
    :rtype: str
    :raise: :class:`CmdError`, if ``ignore_status=False``.
    """
    cmd_result = run(cmd=cmd, timeout=timeout, verbose=verbose, ignore_status=ignore_status,
                     allow_output_check=allow_output_check, shell=shell, env=env,
                     sudo=sudo)
    return cmd_result.stdout
