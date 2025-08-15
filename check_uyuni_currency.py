#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A Nagios/Icinga plugin for checking currency of systems
managed by Uyuni or SUSE Multi-Linux Manager
"""

import argparse
import getpass
import logging
import os
import stat
import math
import sys
from uyuni import UyuniAPIClient

# some global variables
__version__ = "0.7.0"

LOGGER = logging.getLogger("check_uyuni_currency.py")
"""
LOGGER: Logger instance
"""
LOG_LEVEL = None
"""
LOG_LEVEL: Logger level
"""

STATE = 0
system_currency = {}
system_stats = {}


# setting logger and supported API levels
LOGGER = logging.getLogger("check_uyuni_currency")


def get_credentials(login_type, input_file=None):
    """
    retrieve credentials
    """
    if input_file:
        LOGGER.debug("Using authfile")
        try:
            # check filemode and read file
            filemode = oct(stat.S_IMODE(os.lstat(input_file).st_mode))
            if filemode == "0600":
                LOGGER.debug("File permission matches 0600")
                with open(input_file, "r", encoding="utf-8") as auth_file:
                    s_username = auth_file.readline().replace("\n", "")
                    s_password = auth_file.readline().replace("\n", "")
                _credentials = (s_username, s_password)
            else:
                LOGGER.warning("File permissions (%s) not matching 0600!", filemode)
                # sys.sys.exit(1)
        except OSError:
            LOGGER.warning("File non-existent or permissions not 0600!")
            # sys.sys.exit(1)
            LOGGER.debug("Prompting for login credentials as we have a faulty file")
            s_username = input(login_type + " Username: ")
            s_password = getpass.getpass(login_type + " Password: ")
            _credentials = (s_username, s_password)
    elif (
        login_type.upper() + "_LOGIN" in os.environ
        and login_type.upper() + "_PASSWORD" in os.environ
    ):
        # shell variables
        LOGGER.debug("Checking shell variables")
        _credentials = (
            os.environ[login_type.upper() + "_LOGIN"],
            os.environ[login_type.upper() + "_PASSWORD"],
        )
    else:
        # prompt user
        LOGGER.debug("Prompting for login credentials")
        s_username = input(login_type + " Username: ")
        s_password = getpass.getpass(login_type + " Password: ")
        _credentials = (s_username, s_password)
    return _credentials


def set_code(return_code):
    """
    set result code
    """
    global STATE
    STATE = max(STATE, return_code)


def get_return_str():
    """
    get return string
    """
    if STATE == 3:
        result = "UNKNOWN"
    elif STATE == 2:
        result = "CRITICAL"
    elif STATE == 1:
        result = "WARNING"
    else:
        result = "OK"
    return result


def check_value(val, desc, warn, crit):
    """
    compares value to thresholds and sets codes
    """
    LOGGER.debug(
        "Comparing '%s' (%s) to warning/critical thresholds %s/%s)",
            val, desc, warn, crit
    )
    snip = ""
    if val > crit:
        # critical
        snip = f"{desc} critical ({val})"
        set_code(2)
    elif val > warn:
        # warning
        snip = f"{desc} warning ({val})"
        set_code(1)
    else:
        snip = f"{desc} okay ({val})"
    return snip


def check_stats(options):
    """
    check statistics
    """
    LOGGER.debug("System statistics is: %s", system_stats)

    # calculate absolute thresholds
    options.inactive_warn = int(
        math.ceil(float(system_stats["total"]) * (float(options.inactive_warn) / 100))
    )
    options.inactive_crit = int(
        math.ceil(float(system_stats["total"]) * (float(options.inactive_crit) / 100))
    )
    options.outdated_warn = int(
        math.ceil(float(system_stats["total"]) * (float(options.outdated_warn) / 100))
    )
    options.outdated_crit = int(
        math.ceil(float(system_stats["total"]) * (float(options.outdated_crit) / 100))
    )
    LOGGER.debug(
        "Absolute thresholds for inactive (warning/critical): %s/%s",
            options.inactive_warn, options.inactive_crit
    )
    LOGGER.debug(
        "Absolute thresholds for outdated (warning/critical): %s/%s",
            options.outdated_warn, options.outdated_crit
    )

    # check values
    _outdated = check_value(
            int(system_stats["outdated"]),
            "outdated systems",
            options.outdated_warn,
            options.outdated_crit,
    )
    _inactive =  check_value(
            int(system_stats["inactive"]),
            "inactive systems",
            options.inactive_warn,
            options.inactive_crit,
    )
    result = f"{_outdated}, {_inactive}"

    # set performance data
    if options.show_perfdata:
        perfdata = " | "
        perfdata_snip = (
            "{0}"
            "'sys_total'={1};;;; "
            "'sys_outdated'={2};{3};{4};; "
            "'sys_inact'={5};{6};{7};;"
        )
        perfdata = perfdata_snip.format(
            perfdata,
            system_stats["total"],
            system_stats["outdated"],
            options.outdated_warn,
            options.outdated_crit,
            system_stats["inactive"],
            options.inactive_warn,
            options.outdated_warn,
        )
        LOGGER.debug("perfdata is:\n%s",perfdata)
    else:
        perfdata = ""

    # return result and die in a fire
    print(f"{get_return_str()}: {result}{perfdata}")
    sys.exit(STATE)


def check_systems(options):
    """
    check _all_ the systems
    """
    global system_currency
    snip_total = ""
    snip_crit = ""
    snip_bugs = ""
    hostname = ""

    for entry in system_currency:
        hostname = entry["hostname"]
        # set prefix
        if len(system_currency) > 1:
            this_prefix = f"{hostname} "
        else:
            this_prefix = ""

        # total package updates
        if options.total_warn and options.total_crit:
            _total = check_value(
                    entry["all"],
                    f"{this_prefix}total updates",
                    options.total_warn,
                    options.total_crit,
            )
            snip_total = "{snip_total}{_total}"

        # critical package updates
        _security = check_value(
                int(entry["imp"] + entry["crit"] + entry["mod"]),
                f"{this_prefix}critical updates",
                options.security_warn,
                options.security_crit,
        )
        snip_crit = "{snip_crit}{_security}"

        # bug fixes
        _bugs = check_value(
                entry["bug"],
                f"{this_prefix}bug fixes",
                options.bugs_warn,
                options.bugs_crit,
        )
        snip_bugs = "{snip_bugs}{_bugs}"

    # generate perfdata
    if options.show_perfdata:
        # generate perfdata
        perfdata = " | "

        for entry in system_currency:
            # set prefix
            if len(system_currency) > 1:
                this_prefix = f"{entry["hostname"]}_"
            else:
                this_prefix = ""

            perfdata_snip = (
                "{0}"
                "'{1}crit_pkgs'={2};{3};{4};; "
                "'{5}imp_pkgs'={6};{7};{8};; "
                "'{9}mod_pkgs'={10};{11};{12};; "
                "'{13}low_pkgs'={14};;;; "
                "'{15}enh_pkgs'={16};;;; "
                "'{17}bug_pkgs'={18};{19};{20};; "
                "'{21}all_pkgs'={22};{23};{24};; "
                "'{25}score'={26};;;;"
            )
            if not options.total_warn or not options.total_crit:
                options.total_warn = ""
                options.total_crit = ""
            perfdata = perfdata_snip.format(
                perfdata,
                this_prefix,
                int(entry["crit"]),
                int(options.security_warn),
                int(options.security_crit),
                this_prefix,
                int(entry["imp"]),
                int(options.security_warn),
                int(options.security_crit),
                this_prefix,
                int(entry["mod"]),
                int(options.security_warn),
                int(options.security_crit),
                this_prefix,
                int(entry["low"]),
                this_prefix,
                int(entry["enh"]),
                this_prefix,
                int(entry["bug"]),
                int(options.bugs_warn),
                int(options.bugs_crit),
                this_prefix,
                int(entry["all"]),
                options.total_warn,
                options.total_crit,
                this_prefix,
                int(entry["score"]),
            )
        LOGGER.debug("perfdata is:\n%s", perfdata)
    else:
        perfdata = ""

    # return result
    snips = [x for x in [snip_total, snip_crit, snip_bugs] if x != ""]
    if len(options.system) > 1:
        hostname = ""
    else:
        hostname = f"{' for '}{hostname}"
    print(
        f"{get_return_str()}: {str(", ".join(snips))}{hostname}{perfdata}"
    )
    sys.exit(STATE)


def get_currency_data(stats_only=False):
    """
    get _all_ the currency or statistics data
    """
    # global system_currency
    # global system_stats

    # (username, password) = get_credentials("Satellite", options.authfile)
    # satellite_url = "http://{0}/rpc/api".format(options.server)
    # client = xmlrpclib.Server(satellite_url, verbose=options.debug)

    # try:
    #     key = client.auth.login(username, password)
    #     check_if_api_is_supported(client)

    #     if stats_only:
    #         # statistics only
    #         system_stats["total"] = len(client.system.listSystems(key))
    #         system_stats["inactive"] = len(client.system.listInactiveSystems(key))
    #         system_stats["outdated"] = len(client.system.listOutOfDateSystems(key))
    #     else:
    #         # currency data only
    #         system_currency = client.system.getSystemCurrencyScores(key)

    #         # append hostname
    #         counter = 0
    #         for system in system_currency:
    #             system_sid = client.system.getName(key, system["sid"])
    #             LOGGER.debug(
    #                 "DEBUG: Hostname for SID '{0}' seems to be '{1}'".format(
    #                     system["sid"], system_sid["name"]
    #                 )
    #             )
    #             system["hostname"] = system_sid["name"]
    #             # get total package counter
    #             upgradable_pkgs = client.system.listLatestUpgradablePackages(
    #                 key, system["sid"]
    #             )
    #             if len(upgradable_pkgs) > 0:
    #                 system["all"] = len(upgradable_pkgs) - 1
    #             else:
    #                 system["all"] = 0
    #             # drop host if not requested
    #             if options.all_systems is False:
    #                 if system["hostname"] not in options.system:
    #                     system_currency[counter] = None
    #             counter = counter + 1
    #         # clean removed hosts
    #         system_currency = [system for system in system_currency if system is not None]
    # except:
    #     print("Unauthenticated.")
    #     sys.exit(1)


def parse_options(args=None):
    """
    Parses options and arguments.
    """
    desc = """%prog is used to check systems managed by Uyuni or SUSE Multi-Linux Manager for outstanding patches. Login credentials are assigned using the following shell variables:
    UYUNI_LOGIN  username
    UYUNI_PASSWORD  password
    
    It is also possible to create an authfile (permissions 0600) for usage with this script. The first line needs to contain the username, the second line should consist of the appropriate password. If you're not defining variables or an authfile you will be prompted to enter your login information."""

    epilog = """
    Checkout the GitHub page for updates: https://github.com/stdevel/check_uyuni_currency
    """

    parser = argparse.ArgumentParser(description=desc, epilog=epilog)
    parser.add_argument("--version", action="version", version=__version__)

    # define option groups
    gen_opts = parser.add_argument_group(parser, "Generic options")
    space_opts = parser.add_argument_group(parser, "Uyuni options")
    system_opts = parser.add_argument_group(parser, "System options")
    stat_opts = parser.add_argument_group(parser, "Statistic options")

    # -d / --debug
    gen_opts.add_argument(
        "-d",
        "--debug",
        dest="debug",
        default=False,
        action="store_true",
        help="enable debugging outputs",
    )

    # -P / --show-perfdata
    gen_opts.add_argument(
        "-P",
        "--show-perfdata",
        dest="show_perfdata",
        default=False,
        action="store_true",
        help="enables performance data (default: no)",
    )

    # -a / --authfile
    space_opts.add_argument(
        "-a",
        "--authfile",
        dest="authfile",
        metavar="FILE",
        default="",
        help="defines an auth file to use instead of shell variables",
    )

    # -s / --server
    space_opts.add_argument(
        "-s",
        "--server",
        dest="server",
        metavar="SERVER",
        default="localhost",
        help="defines the server to use (default: localhost)",
    )

    # -y / --generic-statistics
    stat_opts.add_argument(
        "-y",
        "--generic-statistics",
        dest="gen_stats",
        default=False,
        action="store_true",
        help="checks for inactive and outdated system statistic metrics (default :no)",
    )

    # -u / --outdated-warning
    stat_opts.add_argument(
        "-u",
        "--outdated-warning",
        dest="outdated_warn",
        default=50,
        metavar="NUMBER",
        type=int,
        help="defines outdated systems warning percentage threshold (default: 50)",
    )

    # -U / --outdated-critical
    stat_opts.add_argument(
        "-U",
        "--outdated-critical",
        dest="outdated_crit",
        default=80,
        metavar="NUMBER",
        type=int,
        help="defines outdated systems critical percentage threshold (default: 80)",
    )

    # -n / --inactive-warning
    stat_opts.add_argument(
        "-n",
        "--inactive-warning",
        dest="inactive_warn",
        default=10,
        metavar="NUMBER",
        type=int,
        help="defines inactive systems warning percentage threshold (default: 10)",
    )

    # -N / --inactive-critical
    stat_opts.add_argument(
        "-N",
        "--inactive-critical",
        dest="inactive_crit",
        default=50,
        metavar="NUMBER",
        type=int,
        help="defines inactive systems critical percentage threshold (default: 50)",
    )

    # -S / --system
    system_opts.add_argument(
        "-S",
        "--system",
        dest="system",
        default=[],
        metavar="SYSTEM",
        action="append",
        help="defines one or multiple system(s) to check",
    )

    # -A / --all-systems
    system_opts.add_argument(
        "-A",
        "--all-systems",
        dest="all_systems",
        default=False,
        action="store_true",
        help="checks all registered systems - USE WITH CAUTION (default: no)",
    )

    # -t / --total-warning
    system_opts.add_argument(
        "-t",
        "--total-warning",
        dest="total_warn",
        metavar="NUMBER",
        type=int,
        help="defines total package update warning threshold (default: empty)",
    )

    # -T / --total-critical
    system_opts.add_argument(
        "-T",
        "--total-critical",
        dest="total_crit",
        metavar="NUMBER",
        type=int,
        help="defines total package update critical threshold (default: empty)",
    )

    # -i / --important-warning
    system_opts.add_argument(
        "-i",
        "--security-warning",
        "--important-warning",
        dest="security_warn",
        metavar="NUMBER",
        type=int,
        default=10,
        help="defines security package (critical, important and moderate security fixes) update warning threshold (default: 10)",
    )

    # -I / --important-critical
    system_opts.add_argument(
        "-I",
        "--security-critical",
        "--important-critical",
        dest="security_crit",
        metavar="NUMBER",
        type=int,
        default=20,
        help="defines security package (critical, important and moderate security fixes) update critical threshold (default: 20)",
    )

    # -b / --bugs-warning
    system_opts.add_argument(
        "-b",
        "--bugs-warning",
        dest="bugs_warn",
        type=int,
        metavar="NUMBER",
        default=25,
        help="defines bug package update warning threshold (default: 25)",
    )

    # -B / --bugs-critical
    system_opts.add_argument(
        "-B",
        "--bugs-critical",
        dest="bugs_crit",
        type=int,
        metavar="NUMBER",
        default=50,
        help="defines bug package update critical threshold (default: 50)",
    )

    # parse options and arguments
    options = parser.parse_args()

    # check system specification
    if (
        options.all_systems is False
        and options.gen_stats is False
        and not options.system
    ):
        LOGGER.error(
            "You need to either specify (a) particular system(s) or all check all systems!"
        )
        sys.exit(1)

    return (options, args)


def main(options, args):
    """
    Main function, starts the logic based on parameters.
    """
    LOGGER.debug("Options: %s", str(options))
    LOGGER.debug("Arguments: %s", str(args))

    # check statistics or systems
    get_currency_data(options.gen_stats)
    if options.gen_stats:
        check_stats(options)
    else:
        check_systems(options)


def cli():
    """
    This functions initializes the CLI interface
    """
    global LOG_LEVEL
    (options, args) = parse_options()

    # set logging level
    logging.basicConfig()
    if options.generic_debug:
        LOG_LEVEL = logging.DEBUG
    else:
        LOG_LEVEL = logging.INFO
    LOGGER.setLevel(LOG_LEVEL)

    main(options, args)


if __name__ == "__main__":
    cli()
