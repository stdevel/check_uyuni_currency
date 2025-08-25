"""
Uyuni XMLRPC API client
"""

from __future__ import (absolute_import, division, print_function)
import logging
import ssl
from xmlrpc.client import Fault, ServerProxy

from exceptions import (
    APILevelNotSupportedException,
    EmptySetException,
    InvalidCredentialsException,
    SessionException,
    SSLCertVerificationError
)

__metaclass__ = type


class UyuniAPIClient:
    """
    Class for communicating with the Uyuni API

    .. class:: UyuniAPIClient
    """

    LOGGER = logging.getLogger("UyuniAPIClient")
    """
    logging: Logger instance
    """
    API_MIN = 24
    """
    int: Minimum supported API version.
    """
    HEADERS = {"User-Agent": "katprep (https://github.com/stdevel/katprep)"}
    """
    dict: Default headers set for every HTTP request
    """

    def __init__(
            self, log_level, hostname, username, password,
            port=443, verify=True
    ):
        """
        Constructor creating the class. It requires specifying a
        hostname, username and password to access the API. After
        initialization, a connected is established.

        :param log_level: log level
        :type log_level: logging
        :param username: API username
        :type username: str
        :param password: corresponding password
        :type password: str
        :param hostname: Uyuni host
        :type hostname: str
        :param port: HTTPS port
        :type port: int
        :param verify: SSL verification
        :type verify: bool
        """
        # set logging
        self.LOGGER.setLevel(log_level)
        self.LOGGER.debug(
            "About to create Uyuni client '%s'@'%s'",
            username, hostname
        )

        # set connection information
        self.LOGGER.debug("Set hostname to '%s'", hostname)
        self.url = f"https://{hostname}:{port}/rpc/api"
        self.verify = verify

        # start session and check API version if Uyuni API
        self._api_key = None
        self._username = username
        self._password = password
        self._session = None
        self._connect()
        self.validate_api_support()


    def _connect(self):
        """
        This function establishes a connection to Uyuni
        """
        # set API session and key
        try:
            if not self.verify:
                context = ssl._create_unverified_context()
            else:
                context = ssl.create_default_context()

            self._session = ServerProxy(self.url, context=context)
            self._api_key = self._session.auth.login(
                self._username, self._password
            )
        except ssl.SSLCertVerificationError as err:
            self.LOGGER.error(err)
            raise SSLCertVerificationError(str(err)) from err
        except Fault as err:
            if err.faultCode == 2950:
                raise InvalidCredentialsException(
                    f"Wrong credentials supplied: {err.faultString!r}"
                ) from err
            raise SessionException(
                f"Generic remote communication error: {err.faultString!r}"
            ) from err


    def validate_api_support(self):
        """
        Checks whether the API version on the Uyuni server is supported.
        Using older versions than API_MIN is not recommended. In this case, an
        exception will be thrown.

        :raises: APILevelNotSupportedException
        """
        try:
            # check whether API is supported
            api_level = self._session.api.getVersion()
            if float(api_level) < self.API_MIN:
                raise APILevelNotSupportedException(
                    f"Your API version ({api_level!r}) doesn't support"
                    "required calls."
                    f"You'll need API version ({self.API_MIN!r}) or higher!"
                )
            self.LOGGER.info("Supported API version %s found.", api_level)
        except ValueError as err:
            self.LOGGER.error(err)
            raise APILevelNotSupportedException(
                "Unable to verify API version"
            ) from err


    def get_hosts(self):
        """
        Returns all system IDs
        """
        try:
            hosts = self._session.system.listSystems(
                self._api_key
            )
            if hosts:
                return [x["id"] for x in hosts]
            raise EmptySetException(
                "No systems found"
            )
        except Fault as err:
            raise SessionException(
                f"Generic remote communication error: {err.faultString!r}"
            ) from err


    def get_hostname_by_id(self, system_id):
        """
        Returns the hostname of a particular system

        :param system_id: profile ID
        :type system_id: int
        """
        try:
            host = self._session.system.getName(
                self._api_key, system_id
            )
            return host["name"]
        except Fault as err:
            if "no such system" in err.faultString.lower():
                raise EmptySetException(
                    f"System not found: {system_id!r}"
                ) from err
            raise SessionException(
                f"Generic remote communication error: {err.faultString!r}"
            ) from err


    def get_host_id(self, hostname):
        """
        Returns the profile ID of a particular system

        :param hostname: system hostname
        :type hostname: str
        """
        try:
            host_id = self._session.system.getId(
                self._api_key, hostname
            )
            if host_id:
                return host_id[0]["id"]
            raise EmptySetException(
                f"System not found: {hostname!r}"
            )
        except Fault as err:
            if "no such system" in err.faultString.lower():
                raise EmptySetException(
                    f"System not found: {hostname!r}"
                ) from err
            raise SessionException(
                f"Generic remote communication error: {err.faultString!r}"
            ) from err


    def get_inactive_hosts(self):
        """
        Returns all inactive system IDs
        """
        try:
            hosts = self._session.system.listInactiveSystems(
                self._api_key
            )
            if hosts:
                _hosts = [x["id"] for x in hosts]
            else:
                _hosts = []
            return _hosts
        except Fault as err:
            raise SessionException(
                f"Generic remote communication error: {err.faultString!r}"
            ) from err


    def get_outdated_hosts(self):
        """
        Returns all outdated system IDs
        """
        try:
            hosts = self._session.system.listOutOfDateSystems(
                self._api_key
            )
            if hosts:
                _hosts = [x["id"] for x in hosts]
            else:
                _hosts = []
            return _hosts
        except Fault as err:
            raise SessionException(
                f"Generic remote communication error: {err.faultString!r}"
            ) from err


    def get_system_currency(self):
        """
        Returns all systems' currency scores
        """
        try:
            scores = self._session.system.getSystemCurrencyScores(
                self._api_key
            )
            if scores:
                return scores
            raise EmptySetException(
                "No systems found"
            )
        except Fault as err:
            raise SessionException(
                f"Generic remote communication error: {err.faultString!r}"
            ) from err


    def get_host_upgrades(self, system_id):
        """
        Returns available package upgrades

        :param system_id: profile ID
        :type system_id: int
        """
        if not isinstance(system_id, int):
            raise EmptySetException(
                "No system found - use system profile IDs"
            )

        try:
            packages = self._session.system.listLatestUpgradablePackages(
                self._api_key, system_id
            )
            self.LOGGER.debug("Found %i upgrades for %s: %s", len(packages), system_id, packages)
            return packages
        except Fault as err:
            if "no such system" in err.faultString.lower():
                raise SessionException(
                    f"System not found: {system_id!r}"
                ) from err
            raise SessionException(
                f"Generic remote communication error: {err.faultString!r}"
            ) from err
