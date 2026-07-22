from asyncio import TimeoutError


__all__ = (
    "SMTPAuthenticationError",
    "SMTPConnectError",
    "SMTPDataError",
    "SMTPException",
    "SMTPHeloError",
    "SMTPNotSupported",
    "SMTPRecipientRefused",
    "SMTPRecipientsRefused",
    "SMTPResponseException",
    "SMTPSenderRefused",
    "SMTPServerDisconnected",
    "SMTPTimeoutError",
    "SMTPConnectTimeoutError",
    "SMTPReadTimeoutError",
    "SMTPConnectResponseError",
)


class SMTPException(Exception):

    def __init__(self, message: str, /) -> None:
        self.message = message
        self.args = (message,)


class SMTPServerDisconnected(SMTPException, ConnectionError):
    pass


class SMTPConnectError(SMTPException, ConnectionError):
    pass


class SMTPTimeoutError(SMTPException, TimeoutError):
    pass


class SMTPConnectTimeoutError(SMTPTimeoutError, SMTPConnectError):
    pass


class SMTPReadTimeoutError(SMTPTimeoutError):
    pass


class SMTPNotSupported(SMTPException):
    pass


class SMTPResponseException(SMTPException):

    def __init__(self, code: int, message: str, /) -> None:
        self.code = code
        self.message = message
        self.args = (code, message)


class SMTPConnectResponseError(SMTPResponseException, SMTPConnectError):
    pass


class SMTPHeloError(SMTPResponseException):
    pass


class SMTPDataError(SMTPResponseException):
    pass


class SMTPAuthenticationError(SMTPResponseException):
    pass


class SMTPSenderRefused(SMTPResponseException):

    def __init__(self, code: int, message: str, sender: str, /) -> None:
        self.code = code
        self.message = message
        self.sender = sender
        self.args = (code, message, sender)


class SMTPRecipientRefused(SMTPResponseException):

    def __init__(self, code: int, message: str, recipient: str, /) -> None:
        self.code = code
        self.message = message
        self.recipient = recipient
        self.args = (code, message, recipient)


class SMTPRecipientsRefused(SMTPException):

    def __init__(self, recipients: list[SMTPRecipientRefused], /) -> None:
        self.recipients = recipients
        self.args = (recipients,)
