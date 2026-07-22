
import asyncio
import email.message
import socket
import ssl
from collections.abc import Iterable, Sequence
from types import TracebackType
from typing import Any, Literal
from .auth import (
    auth_crammd5_verify,
    auth_login_encode,
    auth_plain_encode,
    auth_xoauth2_encode,
)
from .email import (
    extract_recipients,
    extract_sender,
    flatten_message,
    parse_address,
    quote_address,
)
from .errors import (
    SMTPAuthenticationError,
    SMTPConnectError,
    SMTPConnectTimeoutError,
    SMTPException,
    SMTPHeloError,
    SMTPNotSupported,
    SMTPRecipientRefused,
    SMTPRecipientsRefused,
    SMTPResponseException,
    SMTPSenderRefused,
    SMTPServerDisconnected,
    SMTPTimeoutError,
    SMTPConnectResponseError,
)
from .esmtp import parse_esmtp_extensions
from .protocol import SMTPProtocol
from .response import SMTPResponse
from .typing import Default, SMTPStatus, SMTPTokenGenerator, SocketPathType


__all__ = ("SMTP", "SMTP_PORT", "SMTP_TLS_PORT", "SMTP_STARTTLS_PORT")

SMTP_PORT = 25
SMTP_TLS_PORT = 465
SMTP_STARTTLS_PORT = 587
DEFAULT_TIMEOUT = 60


class SMTP:

    AUTH_METHODS: tuple[str, ...] = (
        "cram-md5",
        "plain",
        "login",
    )

    def __init__(
        self,
        *,
        hostname: str | None = None,
        port: int | None = None,
        username: str | bytes | None = None,
        password: str | bytes | None = None,
        oauth_token_generator: SMTPTokenGenerator | None = None,
        local_hostname: str | None = None,
        source_address: tuple[str, int] | None = None,
        timeout: float | None = DEFAULT_TIMEOUT,
        use_tls: bool = False,
        start_tls: bool | None = None,
        validate_certs: bool = True,
        client_cert: str | None = None,
        client_key: str | None = None,
        tls_context: ssl.SSLContext | None = None,
        cert_bundle: str | None = None,
        socket_path: SocketPathType | None = None,
        sock: socket.socket | None = None,
    ) -> None:
        """
        :keyword hostname:  Server name (or IP) to connect to. defaults to "localhost".
        :keyword port: Server port. defaults ``465`` if ``use_tls`` is ``True``,
            ``587`` if ``start_tls`` is ``True``, or ``25`` otherwise.
        :keyword username:  Username to login as after connect.
        :keyword password:  Password for login after connect. Mutually exclusive
            with ``oauth_token_generator``.
        :keyword oauth_token_generator: An async callable that returns an OAuth2
            access token for XOAUTH2 authentication. Mutually exclusive with
            ``password``.
        :keyword local_hostname: The hostname of the client.  If specified, used as the
            FQDN of the local host in the HELO/EHLO command. Otherwise, the result of
            :func:`socket.getfqdn`.
        :keyword source_address: Takes a 2-tuple (host, port) for the socket to bind to
            as its source address before connecting. If the host is '' and port is 0,
            the OS default behavior will be used.
        :keyword timeout: Default timeout value for the connection, in seconds.
            defaults to 60.
        :keyword use_tls: If True, make the initial connection to the server
            over TLS/SSL. Mutually exclusive with ``start_tls``; if the server uses
            STARTTLS, ``use_tls`` should be ``False``.
        :keyword start_tls: Flag to initiate a STARTTLS upgrade on connect.
            If ``None`` (the default), upgrade will be initiated if supported by the
            server.
            If ``True``, and upgrade will be initiated regardless of server support.
            If ``False``, no upgrade will occur.
            Mutually exclusive with ``use_tls``.
        :keyword validate_certs: Determines if server certificates are
            validated. defaults to ``True``.
        :keyword client_cert: Path to client side certificate, for TLS.
        :keyword client_key: Path to client side key, for TLS.
        :keyword tls_context: An existing :py:class:`ssl.SSLContext`, for TLS.
            Mutually exclusive with ``client_cert``/``client_key``.
        :keyword cert_bundle: Path to certificate bundle, for TLS verification.
        :keyword socket_path: Path to a Unix domain socket. Not compatible with
            hostname or port. Accepts str, bytes, or a pathlike object.
        :keyword sock: An existing, connected socket object. If given, none of
            hostname, port, or socket_path should be provided.

        :raises ValueError: mutually exclusive options provided
        """
        self.protocol: SMTPProtocol | None = None
        self.transport: asyncio.BaseTransport | None = None

        self.hostname = hostname
        self.port = port
        self._login_username = username
        self._login_password = password
        self._oauth_token_generator = oauth_token_generator
        self.local_hostname = local_hostname
        self.timeout = timeout
        self.use_tls = use_tls
        self._start_tls_on_connect = start_tls
        self.validate_certs = validate_certs
        self.client_cert = client_cert
        self.client_key = client_key
        self.tls_context = tls_context
        self.cert_bundle = cert_bundle
        self.socket_path = socket_path
        self.sock = sock
        self.source_address = source_address

        self.loop: asyncio.AbstractEventLoop | None = None
        self._connect_lock: asyncio.Lock | None = None
        self.last_helo_response: SMTPResponse | None = None
        self._last_ehlo_response: SMTPResponse | None = None
        self.esmtp_extensions: dict[str, str] = {}
        self.supports_esmtp = False
        self.server_auth_methods: list[str] = []
        self._sendmail_lock: asyncio.Lock | None = None

        self._validate_config()

    async def __aenter__(self) -> "SMTP":
        if not self.is_connected:
            await self.connect()

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if isinstance(exc, (ConnectionError, TimeoutError)):
            self.close()
            return

        try:
            await self.quit()
        except (SMTPServerDisconnected, SMTPResponseException, SMTPTimeoutError):
            pass

    @property
    def is_connected(self) -> bool:
        pass

    @property
    def last_ehlo_response(self) -> SMTPResponse | None:
        pass

    @last_ehlo_response.setter
    def last_ehlo_response(self, response: SMTPResponse) -> None:
        pass

    @property
    def is_ehlo_or_helo_needed(self) -> bool:
        pass

    @property
    def supported_auth_methods(self) -> list[str]:
        pass

    def _update_settings_from_kwargs(
        self,
        hostname: str | Literal[Default.token] | None = Default.token,
        port: int | Literal[Default.token] | None = Default.token,
        username: str | bytes | Literal[Default.token] | None = Default.token,
        password: str | bytes | Literal[Default.token] | None = Default.token,
        oauth_token_generator: SMTPTokenGenerator
        | Literal[Default.token]
        | None = Default.token,
        local_hostname: str | Literal[Default.token] | None = Default.token,
        source_address: tuple[str, int] | Literal[Default.token] | None = Default.token,
        use_tls: bool | None = None,
        start_tls: bool | Literal[Default.token] | None = Default.token,
        validate_certs: bool | None = None,
        client_cert: str | Literal[Default.token] | None = Default.token,
        client_key: str | Literal[Default.token] | None = Default.token,
        tls_context: ssl.SSLContext | Literal[Default.token] | None = Default.token,
        cert_bundle: str | Literal[Default.token] | None = Default.token,
        socket_path: SocketPathType | Literal[Default.token] | None = Default.token,
        sock: socket.socket | Literal[Default.token] | None = Default.token,
    ) -> None:
        pass

    def _validate_config(self) -> None:
        pass

    def _get_default_port(self) -> int:
        pass

    async def _get_default_local_hostname(self) -> str:
        return await asyncio.to_thread(socket.getfqdn)

    async def connect(
        self,
        *,
        hostname: str | Literal[Default.token] | None = Default.token,
        port: int | Literal[Default.token] | None = Default.token,
        username: str | bytes | Literal[Default.token] | None = Default.token,
        password: str | bytes | Literal[Default.token] | None = Default.token,
        oauth_token_generator: SMTPTokenGenerator
        | Literal[Default.token]
        | None = Default.token,
        local_hostname: str | Literal[Default.token] | None = Default.token,
        source_address: tuple[str, int] | Literal[Default.token] | None = Default.token,
        timeout: float | Literal[Default.token] | None = Default.token,
        use_tls: bool | None = None,
        start_tls: bool | Literal[Default.token] | None = Default.token,
        validate_certs: bool | None = None,
        client_cert: str | Literal[Default.token] | None = Default.token,
        client_key: str | Literal[Default.token] | None = Default.token,
        tls_context: ssl.SSLContext | Literal[Default.token] | None = Default.token,
        cert_bundle: str | Literal[Default.token] | None = Default.token,
        socket_path: SocketPathType | Literal[Default.token] | None = Default.token,
        sock: socket.socket | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        pass

    async def _create_connection(self, timeout: float | None) -> SMTPResponse:
        pass

    async def _maybe_start_tls_on_connect(self) -> None:
        pass

    async def _maybe_login_on_connect(self) -> None:
        pass

    async def execute_command(
        self,
        *args: bytes,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        """
        Check that we're connected, if we got a timeout value, and then
        pass the command to the protocol.

        :raises SMTPServerDisconnected: connection lost
        """
        if self.protocol is None:
            raise SMTPServerDisconnected("Server not connected")

        try:
            response = await self.protocol.execute_command(
                *args, timeout=self.timeout if timeout is Default.token else timeout
            )
        except (SMTPServerDisconnected, SMTPTimeoutError):
            self.close()
            raise

        if response.code == SMTPStatus.domain_unavailable:
            self.close()

        return response

    def _get_tls_context(self) -> ssl.SSLContext:
        pass

    def close(self) -> None:
        """
        Closes the connection.
        """
        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()

        if self._connect_lock is not None and self._connect_lock.locked():
            self._connect_lock.release()

        self.protocol = None
        self.transport = None

        self._reset_server_state()

    def get_transport_info(self, key: str) -> Any:
        pass


    async def helo(
        self,
        *,
        hostname: str | None = None,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        """
        Send the SMTP HELO command.
        Hostname to send for this command defaults to the FQDN of the local
        host.

        :raises SMTPHeloError: on unexpected server response code
        """
        if hostname is None:
            if self.local_hostname is None:
                self.local_hostname = await self._get_default_local_hostname()

            hostname = self.local_hostname

        response = self.last_helo_response = await self.execute_command(
            b"HELO", hostname.encode("ascii"), timeout=timeout
        )

        if response.code != SMTPStatus.completed:
            raise SMTPHeloError(response.code, response.message)

        return response

    async def help(
        self, *, timeout: float | Literal[Default.token] | None = Default.token
    ) -> str:
        pass

    async def rset(
        self, *, timeout: float | Literal[Default.token] | None = Default.token
    ) -> SMTPResponse:
        """
        Send an SMTP RSET command, which resets the server's envelope
        (the envelope contains the sender, recipient, and mail data).

        :raises SMTPResponseException: on unexpected server response code
        """
        await self._ehlo_or_helo_if_needed()

        response = await self.execute_command(b"RSET", timeout=timeout)
        if response.code != SMTPStatus.completed:
            raise SMTPResponseException(response.code, response.message)

        return response

    async def noop(
        self, *, timeout: float | Literal[Default.token] | None = Default.token
    ) -> SMTPResponse:
        pass

    async def vrfy(
        self,
        address: str,
        /,
        *,
        options: Iterable[str] | None = None,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        pass

    async def expn(
        self,
        address: str,
        /,
        *,
        options: Iterable[str] | None = None,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        pass

    async def quit(
        self, *, timeout: float | Literal[Default.token] | None = Default.token
    ) -> SMTPResponse:
        pass

    async def mail(
        self,
        sender: str,
        /,
        *,
        options: Iterable[str] | None = None,
        encoding: str = "ascii",
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        """
        Send an SMTP MAIL command, which specifies the message sender and
        begins a new mail transfer session ("envelope").

        :raises SMTPSenderRefused: on unexpected server response code
        """
        await self._ehlo_or_helo_if_needed()

        if options is None:
            options = []

        quoted_sender = quote_address(sender)
        addr_bytes = quoted_sender.encode(encoding)
        options_bytes = [option.encode("ascii") for option in options]

        response = await self.execute_command(
            b"MAIL", b"FROM:" + addr_bytes, *options_bytes, timeout=timeout
        )

        if response.code != SMTPStatus.completed:
            raise SMTPSenderRefused(response.code, response.message, sender)

        return response

    async def rcpt(
        self,
        recipient: str,
        /,
        *,
        options: Iterable[str] | None = None,
        encoding: str = "ascii",
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        """
        Send an SMTP RCPT command, which specifies a single recipient for
        the message. This command is sent once per recipient and must be
        preceded by 'MAIL'.

        :raises SMTPRecipientRefused: on unexpected server response code
        """
        await self._ehlo_or_helo_if_needed()

        if options is None:
            options = []

        quoted_recipient = quote_address(recipient)
        addr_bytes = quoted_recipient.encode(encoding)
        options_bytes = [option.encode("ascii") for option in options]

        response = await self.execute_command(
            b"RCPT", b"TO:" + addr_bytes, *options_bytes, timeout=timeout
        )

        if response.code not in (SMTPStatus.completed, SMTPStatus.will_forward):
            raise SMTPRecipientRefused(response.code, response.message, recipient)

        return response

    async def data(
        self,
        message: str | bytes,
        /,
        *,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        """
        Send an SMTP DATA command, followed by the message given.
        This method transfers the actual email content to the server.

        :raises SMTPDataError: on unexpected server response code
        :raises SMTPServerDisconnected: connection lost
        """
        if self.protocol is None:
            raise SMTPServerDisconnected("Connection lost")

        await self._ehlo_or_helo_if_needed()

        if timeout is Default.token:
            timeout = self.timeout

        if isinstance(message, str):
            message = message.encode("ascii")

        try:
            return await self.protocol.execute_data_command(message, timeout=timeout)
        except (SMTPServerDisconnected, SMTPTimeoutError):
            self.close()
            raise


    async def ehlo(
        self,
        *,
        hostname: str | None = None,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        """
        Send the SMTP EHLO command.
        Hostname to send for this command defaults to the FQDN of the local
        host.

        :raises SMTPHeloError: on unexpected server response code
        """
        if hostname is None:
            if self.local_hostname is None:
                self.local_hostname = await self._get_default_local_hostname()

            hostname = self.local_hostname

        response = await self.execute_command(
            b"EHLO", hostname.encode("ascii"), timeout=timeout
        )

        if response.code != SMTPStatus.completed:
            raise SMTPHeloError(response.code, response.message)

        self.last_ehlo_response = response

        return response

    def supports_extension(self, extension: str, /) -> bool:
        """
        Tests if the server supports the ESMTP service extension given.
        """
        return extension.lower() in self.esmtp_extensions

    async def _ehlo_or_helo_if_needed(self) -> None:
        """
        Call self.ehlo() and/or self.helo() if needed.

        If there has been no previous EHLO or HELO command this session, this
        method tries ESMTP EHLO first.
        """
        if self.is_ehlo_or_helo_needed:
            try:
                await self.ehlo()
            except SMTPHeloError as exc:
                if self.is_connected:
                    await self.helo()
                else:
                    raise exc

    def _reset_server_state(self) -> None:
        """
        Clear stored information about the server.
        """
        self.last_helo_response = None
        self._last_ehlo_response = None
        self.esmtp_extensions = {}
        self.supports_esmtp = False
        self.server_auth_methods = []

    async def starttls(
        self,
        *,
        server_hostname: str | None = None,
        validate_certs: bool | None = None,
        client_cert: str | Literal[Default.token] | None = Default.token,
        client_key: str | Literal[Default.token] | None = Default.token,
        cert_bundle: str | Literal[Default.token] | None = Default.token,
        tls_context: ssl.SSLContext | Literal[Default.token] | None = Default.token,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        pass


    async def login(
        self,
        username: str | bytes,
        password: str | bytes,
        /,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        pass

    async def auth_crammd5(
        self,
        username: str | bytes,
        password: str | bytes,
        /,
        *,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        pass

    async def auth_plain(
        self,
        username: str | bytes,
        password: str | bytes,
        /,
        *,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        pass

    async def auth_login(
        self,
        username: str | bytes,
        password: str | bytes,
        /,
        *,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        pass

    async def auth_xoauth2(
        self,
        username: str | bytes,
        access_token: str | bytes,
        /,
        *,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> SMTPResponse:
        pass

    async def sendmail(
        self,
        sender: str,
        recipients: str | Sequence[str],
        message: str | bytes,
        /,
        *,
        mail_options: Iterable[str] | None = None,
        rcpt_options: Iterable[str] | None = None,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> tuple[dict[str, SMTPResponse], str]:
        """
        This command performs an entire mail transaction.

        The arguments are:
            - sender: The address sending this mail.
            - recipients: A list of addresses to send this mail to.  A bare
                string will be treated as a list with 1 address.
            - message: The message string to send.
            - mail_options: List of options (such as ESMTP 8bitmime) for the
                MAIL command.
            - rcpt_options: List of options (such as DSN commands) for all the
                RCPT commands.

        message must be a string containing characters in the ASCII range.
        The string is encoded to bytes using the ascii codec, and lone \\\\r
        and \\\\n characters are converted to \\\\r\\\\n characters.

        If there has been no previous HELO or EHLO command this session, this
        method tries EHLO first.

        This method will return normally if the mail is accepted for at least
        one recipient.  It returns a tuple consisting of:

            - an error dictionary, with one entry for each recipient that was
                refused.  Each entry contains a tuple of the SMTP error code
                and the accompanying error message sent by the server.
            - the message sent by the server in response to the DATA command
                (often containing a message id)

        Example:

            >>> smtp = aiosmtplib.SMTP(hostname="127.0.0.1", port=1025)
            >>> recipients = ["one@one.org", "two@two.org", "3@three.org"]
            >>> message = "From: Me@my.org\\nSubject: testing\\nHello World"
            >>> async def connect_and_send():
            ...     await smtp.connect()
            ...     await smtp.sendmail("me@my.org", recipients, message)
            ...     return await smtp.quit()
            >>> asyncio.run(connect_and_send())
            SMTPResponse(code=221, message='Bye')

        In the above example, the message was accepted for delivery for all
        three addresses. If delivery had been only successful to two
        of the three addresses, and one was rejected, the response would look
        something like::

            (
                {"nobody@three.org": (550, "User unknown")},
                "Written safely to disk. #902487694.289148.12219.",
            )


        If delivery is not successful to any addresses,
        :exc:`.SMTPRecipientsRefused` is raised.

        If :exc:`.SMTPResponseException` is raised by this method, we try to
        send an RSET command to reset the server envelope automatically for
        the next attempt.

        :raises SMTPRecipientsRefused: delivery to all recipients failed
        :raises SMTPResponseException: on invalid response
        """
        if isinstance(recipients, str):
            recipients = [recipients]
        if mail_options is None:
            mail_options = []
        else:
            mail_options = list(mail_options)
        if rcpt_options is None:
            rcpt_options = []
        else:
            rcpt_options = list(rcpt_options)

        if any(option.lower() == "smtputf8" for option in mail_options):
            mailbox_encoding = "utf-8"
        else:
            mailbox_encoding = "ascii"

        if self._sendmail_lock is None:
            self._sendmail_lock = asyncio.Lock()

        async with self._sendmail_lock:
            await self._ehlo_or_helo_if_needed()

            if mailbox_encoding == "utf-8" and not self.supports_extension("smtputf8"):
                raise SMTPNotSupported("SMTPUTF8 is not supported by this server")

            if self.supports_extension("size"):
                message_len = len(message)
                size_option = f"size={message_len}"
                mail_options.insert(0, size_option)

            try:
                await self.mail(
                    sender,
                    options=mail_options,
                    encoding=mailbox_encoding,
                    timeout=timeout,
                )
                recipient_errors = await self._send_recipients(
                    recipients, rcpt_options, encoding=mailbox_encoding, timeout=timeout
                )
                response = await self.data(message, timeout=timeout)
            except (SMTPResponseException, SMTPRecipientsRefused) as exc:
                try:
                    await self.rset(timeout=timeout)
                except (ConnectionError, SMTPResponseException):
                    pass
                raise exc

        return recipient_errors, response.message

    async def _send_recipients(
        self,
        recipients: Sequence[str],
        options: Iterable[str],
        encoding: str = "ascii",
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> dict[str, SMTPResponse]:
        """
        Send the recipients given to the server. Used as part of
        :meth:`.sendmail`.
        """
        recipient_errors: list[SMTPRecipientRefused] = []
        for address in recipients:
            try:
                await self.rcpt(
                    address, options=options, encoding=encoding, timeout=timeout
                )
            except SMTPRecipientRefused as exc:
                recipient_errors.append(exc)

        if len(recipient_errors) == len(recipients):
            raise SMTPRecipientsRefused(recipient_errors)

        formatted_errors = {
            err.recipient: SMTPResponse(err.code, err.message)
            for err in recipient_errors
        }

        return formatted_errors

    async def send_message(
        self,
        message: email.message.EmailMessage | email.message.Message,
        /,
        *,
        sender: str | None = None,
        recipients: str | Sequence[str] | None = None,
        mail_options: Iterable[str] | None = None,
        rcpt_options: Iterable[str] | None = None,
        timeout: float | Literal[Default.token] | None = Default.token,
    ) -> tuple[dict[str, SMTPResponse], str]:
        r"""
        Sends an :py:class:`email.message.EmailMessage` object.

        Arguments are as for :meth:`.sendmail`, except that message is an
        :py:class:`email.message.EmailMessage` object.  If sender is None or
        recipients is None, these arguments are taken from the headers of the
        EmailMessage as described in RFC 2822.  Regardless of the values of sender
        and recipients, any Bcc field (or Resent-Bcc field, when the message is a
        resent) of the EmailMessage object will not be transmitted.  The EmailMessage
        object is then serialized using :py:class:`email.generator.Generator` and
        :meth:`.sendmail` is called to transmit the message.

        'Resent-Date' is a mandatory field if the message is resent (RFC 2822
        Section 3.6.6). In such a case, we use the 'Resent-\*' fields.
        However, if there is more than one 'Resent-' block there's no way to
        unambiguously determine which one is the most recent in all cases,
        so rather than guess we raise a ``ValueError`` in that case.

        :raises ValueError:
            on more than one Resent header block
            on no sender kwarg or From header in message
            on no recipients kwarg or To, Cc or Bcc header in message
        :raises SMTPRecipientsRefused: delivery to all recipients failed
        :raises SMTPResponseException: on invalid response
        """
        if mail_options is None:
            mail_options = []
        else:
            mail_options = list(mail_options)

        if sender is None:
            sender = extract_sender(message)
        if sender is None:
            raise ValueError("No From header provided in message")

        if isinstance(recipients, str):
            recipients = [recipients]
        elif recipients is None:
            recipients = extract_recipients(message)
        if not recipients:
            raise ValueError("No recipient headers provided in message")

        await self._ehlo_or_helo_if_needed()

        try:
            sender.encode("ascii")
            "".join(recipients).encode("ascii")
        except UnicodeEncodeError:
            utf8_required = True
        else:
            utf8_required = False

        if utf8_required:
            if not self.supports_extension("smtputf8"):
                raise SMTPNotSupported(
                    "An address containing non-ASCII characters was provided, but "
                    "SMTPUTF8 is not supported by this server"
                )
            elif "smtputf8" not in [option.lower() for option in mail_options]:
                mail_options.append("SMTPUTF8")

        if self.supports_extension("8BITMIME"):
            if "body=8bitmime" not in [option.lower() for option in mail_options]:
                mail_options.append("BODY=8BITMIME")
            cte_type = "8bit"
        else:
            cte_type = "7bit"

        flat_message = flatten_message(message, utf8=utf8_required, cte_type=cte_type)

        return await self.sendmail(
            sender,
            recipients,
            flat_message,
            mail_options=mail_options,
            rcpt_options=rcpt_options,
            timeout=timeout,
        )

    def sendmail_sync(
        self, *args: Any, **kwargs: Any
    ) -> tuple[dict[str, SMTPResponse], str]:
        """
        Synchronous version of :meth:`.sendmail`. This method starts
        an event loop to connect, send the message, and disconnect.
        """

        async def sendmail_coroutine() -> tuple[dict[str, SMTPResponse], str]:
            async with self:
                return await self.sendmail(*args, **kwargs)

        return asyncio.run(sendmail_coroutine())

    def send_message_sync(
        self, *args: Any, **kwargs: Any
    ) -> tuple[dict[str, SMTPResponse], str]:
        pass
