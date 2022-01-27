#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Modified from original in 2020 by Scott Pickering <s.pickering.2@warwick.ac.uk>
# Reproduced under ther terms of the original GNU Lesser General Public License
# as set out below.
#
# Changes are as follows:
# - Default format has been modified to message only, no timestamp 
# - Default prompt character has been changed to none
# - Code for invoking pyterm for a remote application has been removed.
# - Default messages have been removed on start and exit
#  
# Copyright (C) 2014  Oliver Hahm <oliver.hahm@inria.fr>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA


try:
    import configparser
except ImportError:
    import ConfigParser as configparser

import cmd
import errno
import serial
import socket
import sys
import threading
import readline
import time
import logging
import os
import argparse
import re
import codecs
import platform
import _thread

try:
    serial.Serial
except AttributeError:
    print("\033[1;37;41m\n")
    print("Something went terribly wrong when loading the pyserial package.")
    print("There is a good chance that you installed the 'serial' package instead")
    print("of 'pyserial'. Try running 'pip uninstall serial && pip install pyserial'")
    print("\033[0m")
    sys.exit(1)



class Protocol():
    def __init__(self):
        pass

class ReconnectingClientFactory():
    def __init__(self):
        pass

# set some default options
defaulthostname = platform.node()

# default serial port
defaultport = "/dev/ttyUSB0"

# default baudrate for serial connection
defaultbaud = 115200

# directory to store configuration and log files
defaultdir = os.environ['HOME'] + os.path.sep + '.pyterm'

# configuration file name
defaultfile = "pyterm-" + defaulthostname + ".conf"

# logging subfolder
defaultrunname = "default-run"

# default logging prefix format string
# default_fmt_str = '%(asctime)s # %(message)s'
default_fmt_str = '%(message)s'

# default newline setting
defaultnewline = "LF"

# default prompt character
# defaultprompt = '>'
defaultprompt = ''

# repeat command on empty line instead of sending the line
defaultrepeat_cmd_empty_line = True
defaultreconnect = True


class SerCmd(cmd.Cmd):
    """Main class for pyterm based on Python's Cmd class.

    Runs an interactive terminal that transfer between stdio and serial
    port.
    """

    def __init__(self, port=None, baudrate=None, toggle=None, tcp_serial=None,
                 confdir=None, conffile=None, host=None, run_name=None,
                 log_dir_name=None, newline=None, formatter=None,
                 set_rts=None, set_dtr=None, serprompt=None,
                 repeat_command_on_empty_line=defaultrepeat_cmd_empty_line,
                 reconnect=defaultreconnect):
        """Constructor.

        Args:
            port (str):         serial port
            baudrate (int):     serial baudrate
            tcp_serial (iht):   TCP port to connect to (alternatively)
            confdir (str):      configuration directory
            conffile (str):     configuration file name
            host (str):         local host name
            run_name (str):     identifier for log files subdirectory

        """

        # initialize class members
        cmd.Cmd.__init__(self)
        self.port = port
        self.baudrate = baudrate
        self.toggle = toggle
        self.set_rts = set_rts
        self.set_dtr = set_dtr
        self.tcp_serial = tcp_serial
        self.configdir = confdir
        self.configfile = conffile
        self.host = host
        self.run_name = run_name
        self.log_dir_name = log_dir_name
        self.newline = newline
        self.serprompt = serprompt
        self.repeat_command_on_empty_line = repeat_command_on_empty_line
        self.reconnect = reconnect
        if formatter is not None:
            self.fmt_str = formatter

        if not self.host:
            self.host = defaulthostname

        if not self.run_name:
            self.run_name = defaultrunname

        if not self.log_dir_name:
            self.log_dir_name = self.host

        if not os.path.exists(self.configdir):
            os.makedirs(self.configdir)

        self.aliases = dict()
        self.triggers = dict()
        self.filters = []
        self.ignores = []
        self.json_regs = dict()
        self.init_cmd = []
        self.load_config()
        if not hasattr(self, "fmt_str") or self.fmt_str is None:
            self.fmt_str = default_fmt_str
        else:
            self.fmt_str = str(self.fmt_str.replace('"', '')) + "%(message)s"

        # check for a history file
        try:
            readline.read_history_file()
        except IOError:
            pass

        # create Logging object
        my_millis = "%.4f" % (time.time())
        date_str = '%s.%s' % (time.strftime('%Y%m%d-%H.%M.%S'), my_millis[-4:])
        self.startup = date_str
        # create formatter
        formatter = logging.Formatter(self.fmt_str)

        directory = self.configdir + os.path.sep + self.log_dir_name
        if not os.path.exists(directory):
            os.makedirs(directory)
        logging.basicConfig(filename=directory + os.path.sep + self.run_name +
                            '.log', level=logging.DEBUG, format=self.fmt_str)
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)

        # create logger
        self.logger = logging.getLogger('')
        self.logger.setLevel(logging.INFO)

        # add formatter to ch
        ch.setFormatter(formatter)
        # add ch to logger
        self.logger.addHandler(ch)

    def preloop(self):
        """Executed bat program start.
        """

        # if no serial or TCP is specified use default serial port
        if not self.port and not self.tcp_serial:
            sys.stderr.write("No port specified, using default (%s)!\n"
                             % (defaultport))
            self.port = defaultport
        if self.port:
            connected = False
            # self.logger.info("Connect to serial port %s" % self.port)
            while not connected:
                try:
                    self.serial_connect()
                except serial.SerialException as e:
                    self.logger.error("%s", e.strerror)
                    if (not self.reconnect) or (e.errno == errno.ENOENT):
                        sys.exit(e.errno)
                    self.logger.info("Trying to reconnect to {} in 10 sec"
                                     .format(self.port))
                    time.sleep(10)
                except OSError as e:
                    self.logger.error("Cannot connect to serial port {}: {}"
                                      .format(self.port, e.strerror))
                    sys.exit(e.errno)
                except Exception as e:
                    self.logger.error("Unexpected exception {}".format(e))
                    sys.exit(1)
                else:
                    connected = True

        # wait until connection is established and fire startup
        # commands to the node
        time.sleep(1)
        for command in self.init_cmd:
            self.logger.debug("WRITE ----->>>>>> '" + command + "'\n")
            self.onecmd(self.precmd(command))

        # start serial->console thread
        receiver_thread = threading.Thread(target=self.reader)
        receiver_thread.setDaemon(1)
        receiver_thread.start()

    def precmd(self, line):
        """Check for command prefixes to distinguish between Pyterm
        interal commands and commands that should be send to the node.
        """
        self.logger.debug("processing line #%s#" % line)
        if (line.startswith("/")):
            return "PYTERM_" + line[1:]
        return line

    def emptyline(self):
        """Either send empty line or repeat previous command.

        Behavior can be configured with `repeat_command_on_empty_line`.
        """
        if self.repeat_command_on_empty_line:
            super().emptyline()
        else:
            self.default('')

    def default(self, line):
        """In case of no Pyterm specific prefix is detected, split
        string by colons and send it to the node.
        """
        self.logger.debug("%s is no pyterm command, sending to default "
                          "out" % line)
        for tok in line.split(';'):
            tok = self.get_alias(tok)
            if sys.version_info[0] == 2:
                self.ser.write((tok.strip() + "\n").decode("utf-8").encode("utf-8"))
            else:
                self.ser.write((tok.strip() + "\n").encode("utf-8"))

    def do_help(self, line):
        """Do not use Cmd's internal help function, but redirect to the
        node.
        """
        self.ser.write("help\n".encode("utf-8"))

    def do_EOF(self, line):
        """Handle EOF (Ctrl+D) nicely."""
        self.logger.debug("Received EOF")
        self.do_PYTERM_exit("")
        sys.exit(0)

    def complete_date(self, text, line, begidx, endidm):
        """Auto completion for date string.
        """
        date = time.strftime("%Y-%m-%d %H:%M:%S")
        return ["%s" % (date)]

    def do_PYTERM_exit(self, line, unused=None):
        """Pyterm command: Exit Pyterm.
        """
        # self.logger.info("Exiting Pyterm")
        # save history file
        readline.write_history_file()
        # shut down twisted if running
        try:
            if reactor.running:
                reactor.callFromThread(reactor.stop)
        except NameError:
            pass

        if self.tcp_serial:
            self.ser.close()
        return True


    def get_alias(self, tok):
        """Internal function to check for aliases.
        """
        for alias in self.aliases:
            if tok.split()[0] == alias:
                return self.aliases[alias] + tok[len(alias):]
        return tok

    def load_config(self):
        """Internal function to laod configuration from file.
        """
        self.config = configparser.ConfigParser()
        cf = os.path.join(self.configdir, self.configfile)
        self.config.read(cf)
        logging.getLogger("").info("Reading file: %s" % cf)

        for sec in self.config.sections():
            if sec == "filters":
                for opt in self.config.options(sec):
                    self.filters.append(
                        re.compile(self.config.get(sec, opt)))
            if sec == "ignores":
                for opt in self.config.options(sec):
                    self.ignores.append(
                        re.compile(self.config.get(sec, opt)))
            if sec == "json_regs":
                for opt in self.config.options(sec):
                    self.logger.info("add json regex for %s"
                                     % self.config.get(sec, opt))
                    self.json_regs[opt] = re.compile(self.config.get(sec, opt))
            if sec == "aliases":
                for opt in self.config.options(sec):
                    self.aliases[opt] = self.config.get(sec, opt)
            if sec == "triggers":
                for opt in self.config.options(sec):
                    self.triggers[re.compile(opt)] = \
                        self.config.get(sec, opt)
            if sec == "init_cmd":
                for opt in self.config.options(sec):
                    self.init_cmd.append(self.config.get(sec, opt))
            else:
                for opt in self.config.options(sec):
                    if not hasattr(self, opt):
                        setattr(self, opt, self.config.get(sec, opt))

    def process_line(self, line):
        """Processes a valid line from node that should be printed and
        possibly forwarded.

        Args:
            line (str): input from node.
        """
        self.logger.info(line)
        # check if line matches a trigger and fire the command(s)
        for trigger in self.triggers:
            self.logger.debug("comparing input %s to trigger %s"
                              % (line, trigger.pattern))
            m = trigger.search(line)
            if m:
                self.onecmd(self.precmd(self.triggers[trigger]))

        # ckecking if the line should be sent as JSON object to a tcp
        # server
        if (len(self.json_regs)) and self.factory and self.factory.myproto:
            for j in self.json_regs:
                m = self.json_regs[j].search(line)
                if m:
                    try:
                        json_obj = '{"jid":%d, ' % int(j)
                    except ValueError:
                        sys.stderr.write("Invalid JID: %s\n" % j)
                        break
                    json_obj += '"raw":"%s", ' % line
                    json_obj += '"date":%s, ' % int(time.time()*1000)
                    for g in m.groupdict():
                        try:
                            json_obj += '"%s":%d, ' \
                                        % (g, int(m.groupdict()[g]))
                        except ValueError:
                            json_obj += '"%s":"%s", ' \
                                        % (g, m.groupdict()[g])

                    # eliminate the superfluous last ", "
                    json_obj = json_obj[:-2]

                    json_obj += "}"
                    self.factory.myproto.sendMessage(json_obj)

    def handle_line(self, line):
        """Handle line from node and check for further processing
        requirements.

        Args:
            line (str): input line from node.
        """
        # First check if line should be ignored
        ignored = False
        if (len(self.ignores)):
            for i in self.ignores:
                if i.search(line):
                    ignored = True
                    break
        # now check if filter rules should be applied
        if (len(self.filters)):
            for r in self.filters:
                if r.search(line):
                    if not ignored:
                        self.process_line(line)
        # if neither nor applies print the line
        else:
            if not ignored:
                self.process_line(line)

    def serial_connect(self):
        self.ser = serial.Serial(port=self.port, dsrdtr=0, rtscts=0)
        self.ser.baudrate = self.baudrate

        if self.toggle:
            self.ser.setDTR(0)
            self.ser.setRTS(0)

        if self.set_rts == 1 or self.set_rts == 0:
            self.ser.setRTS(self.set_rts)

        if self.set_dtr == 1 or self.set_dtr == 0:
            self.ser.setDTR(self.set_dtr)

    def reader(self):
        """Serial or TCP reader.
        """
        output = ""
        crreceived = False
        nlreceived = False
        while (1):
            # check if serial port can be accessed.
            try:
                sr = codecs.getreader("UTF-8")(self.ser,
                                               errors='replace')
                c = sr.read(1)
            # try to re-open it with a timeout of 1s otherwise
            except (serial.SerialException, ValueError):
                self.logger.warning("Mote disconnected from server")
                self.ser.close()
                os._exit(0)
            if c == '\r':
                if (self.newline == "LFCR" and nlreceived) or (self.newline == "CR"):
                    self.handle_line(output)
                    output = ""
            elif c == '\n':
                if (self.newline == "CRLF" and crreceived) or (self.newline == "LF"):
                    self.handle_line(output)
                    output = ""
            elif c == self.serprompt and output == "":
                sys.stdout.write('%c ' % self.serprompt)
                sys.stdout.flush()
            else:
                output += c

            # Hack to correctly handle reset ANSI escape code in the stream
            # When the reset escape sequence is detected, it is written and
            # flushed immediately to stdout
            if output == '\033[0m':
                sys.stdout.write(output)
                sys.stdout.flush()
                output = ""

            crreceived = c == '\r'
            nlreceived = c == '\n'


class PytermProt(Protocol):
    def __init__(self, factory):
        self.factory = factory

    def connectionMade(self):
        print("writing to transport")
        self.transport.write("hostname: %s\n" % (self.factory.shell.host))

    def dataReceived(self, data):
        sys.stdout.write(data)
        if(data.strip() == "/exit"):
            reactor.callLater(2, self.factory.shell.do_PYTERM_exit, data)
        else:
            self.factory.shell.ser.write(data + "\n")

    def sendMessage(self, msg):
        self.transport.writeSomeData("%d#%s\n" % (len(msg), msg))


class PytermClientFactory(ReconnectingClientFactory):

    def __init__(self, shell=None):
        self.myproto = None
        self.shell = shell

    def buildProtocol(self, addr):
        print('Connected.')
        self.resetDelay()
        self.myproto = PytermProt(self)
        return self.myproto

    def clientConnectionLost(self, connector, reason):
        if reactor.running:
            print('Lost connection.  Reason:', reason)
        ReconnectingClientFactory.clientConnectionLost(self, connector,
                                                       reason)

    def clientConnectionFailed(self, connector, reason):
        print('Connection failed. Reason:', reason)
        ReconnectingClientFactory.clientConnectionFailed(self,
                                                         connector,
                                                         reason)


class fdsocket(socket.socket):
    def read(self, bufsize):
        return self.recv(bufsize)

    def write(self, string):
        try:
            return self.sendall(string)
        except socket.error as e:
            logging.getLogger("").warning("Error in TCP connection (%s), "
                                          "closing down" % str(e))
            self.close()
            sys.exit(0)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Pyterm - The Python "
                                                 "terminal program")
    parser.add_argument("-p", "--port",
                        help="Specifies the serial port to use, default is %s"
                        % defaultport,
                        default=defaultport)
    parser.add_argument("-ts", "--tcp-serial",
                        help="Connect to a TCP port instead of a serial port. "
                        "Format is <hostname>:<port>. If the colon is missing"
                        " host defaults to \"localhost\"")
    parser.add_argument("-b", "--baudrate",
                        help="Specifies baudrate for the serial port, default "
                        "is %s" % defaultbaud,
                        default=defaultbaud)
    parser.add_argument("-tg", "--toggle",
                        action="store_true",
                        help="toggles the DTR and RTS pin of the serial line "
                        "when connecting, default is not toggling the pins")
    parser.add_argument("-sr", "--set-rts",
                        dest="set_rts",
                        type=int,
                        action="store",
                        default=None,
                        help="Specifies the value of RTS pin")
    parser.add_argument("-sd", "--set-dtr",
                        dest="set_dtr",
                        type=int,
                        action="store",
                        default=None,
                        help="Specifies the value of DTR pin")
    parser.add_argument('-d', '--directory',
                        help="Specify the Pyterm directory, default is %s"
                        % defaultdir,
                        default=defaultdir)
    parser.add_argument("-c", "--config",
                        help="Specify the config filename, default is %s"
                        % defaultfile,
                        default=defaultfile)
    parser.add_argument("-f", "--format",
                        help="The format prefix for output and log entries, "
                        "default is %s"
                        % str.replace(default_fmt_str, '%', '%%'))
    parser.add_argument("-np", "--noprefix",
                        action="store_true",
                        help="Disable format prefix, raw output")
    parser.add_argument("-s", "--server",
                        help="Connect via TCP to this server to send output "
                        "as JSON")
    parser.add_argument("-P", "--tcp_port", type=int,
                        help="Port at the JSON server")
    parser.add_argument("-H", "--host",
                        help="Hostname of this maschine")
    parser.add_argument("-rn", "--run-name",
                        help="Run name, used for logfile")
    parser.add_argument("-ln", "--log-dir-name",
                        help="Log directory name (default is hostname + "
                        "run-name e.g. %s/<hostname>/<run-name>)" % defaultdir)
    parser.add_argument("-nl", "--newline",
                        help="Specify the newline character(s) as a combination "
                        "of CR and LF. Examples: -nl=LF, -nl=CRLF. "
                        "(Default is %s)" % defaultnewline,
                        default=defaultnewline)
    parser.add_argument("-pr", "--prompt",
                        help="The expected prompt character, default is none for "
                        "this modified version of Pyterm")

    # Keep help message in sync if changing the default
    parser.add_argument("--repeat-command-on-empty-line",
                        dest='repeat_command_on_empty_line',
                        action='store_true',
                        help="Repeat command on empty line (Default)")
    parser.add_argument("--no-repeat-command-on-empty-line",
                        dest='repeat_command_on_empty_line',
                        action="store_false",
                        help="Do not repeat command on empty line")
    parser.add_argument("--reconnect",
                        dest='reconnect',
                        action='store_true',
                        help="Try to reconnect when failing on connection "
                             "setup (Default)")
    parser.add_argument("--no-reconnect",
                        dest='reconnect',
                        action="store_false",
                        help="Do not try to reconnect when failing on "
                             "connection setup (Default)")
    parser.set_defaults(
        repeat_command_on_empty_line=defaultrepeat_cmd_empty_line,
        reconnect=defaultreconnect)

    args = parser.parse_args()

    if args.noprefix:
        args.format = ""
    myshell = SerCmd(args.port, args.baudrate, args.toggle, args.tcp_serial,
                     args.directory, args.config, args.host, args.run_name,
                     args.log_dir_name, args.newline, args.format,
                     args.set_rts, args.set_dtr, args.prompt,
                     args.repeat_command_on_empty_line)
    myshell.prompt = ''

    try:
        myshell.cmdloop()
    except KeyboardInterrupt:
        myshell.do_PYTERM_exit(None)
