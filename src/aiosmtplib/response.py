
from typing import NamedTuple


__all__ = ("SMTPResponse",)


class SMTPResponse(NamedTuple):

    code: int
    message: str

    def __str__(self) -> str:
        return f"{self.code} {self.message}"
