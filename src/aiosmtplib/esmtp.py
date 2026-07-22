
import re


__all__ = ("parse_esmtp_extensions",)


OLDSTYLE_AUTH_REGEX = re.compile(r"auth=(?P<auth>.*)", flags=re.I)


def parse_esmtp_extensions(message: str) -> tuple[dict[str, str], list[str]]:
    """
    Parse an EHLO response from the server into a dict of {extension: params}
    and a list of auth method names.

    It might look something like:

         220 size.does.matter.af.MIL (More ESMTP than Crappysoft!)
         EHLO heaven.af.mil
         250-size.does.matter.af.MIL offers FIFTEEN extensions:
         250-8BITMIME
         250-PIPELINING
         250-DSN
         250-ENHANCEDSTATUSCODES
         250-EXPN
         250-HELP
         250-SAML
         250-SEND
         250-SOML
         250-TURN
         250-XADR
         250-XSTA
         250-ETRN
         250-XGEN
         250 SIZE 51200000
    """
    esmtp_extensions: dict[str, str] = {}
    auth_types: list[str] = []

    for line in message.split("\n")[1:]:
        line = line.strip()
        if not line:
            continue

        oldstyle_auth = OLDSTYLE_AUTH_REGEX.fullmatch(line)
        if oldstyle_auth is not None:
            params = oldstyle_auth["auth"]
            esmtp_extensions["auth"] = params
            auth_types.extend(method.lower() for method in params.split())
            continue

        keyword, _, params = line.partition(" ")
        keyword = keyword.lower()
        esmtp_extensions[keyword] = params

        if keyword == "auth":
            auth_types.extend(method.lower() for method in params.split())

    return esmtp_extensions, auth_types
