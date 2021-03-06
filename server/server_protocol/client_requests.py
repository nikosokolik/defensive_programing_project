import abc
import enum
import struct
from dataclasses import dataclass
from typing import ClassVar, Callable
from server_protocol.utils import generate_pack, ProtocolError


class RequestCode(enum.Enum):
    SIGNUP = 1000
    USER_LIST = 1001
    USER_PUBKEY = 1002
    MESSAGE_REQUEST = 1003
    READ_MESSAGES = 1004


class ClientRequest(abc.ABC):
    """
    A class that represents any struct that will be used by the server protocol. This provides the unpack function,
    which allows easy loading of data into struct according to the format of the header.
    """

    format: ClassVar[struct.Struct]

    @classmethod
    def unpack(cls, data: bytes):
        try:
            if hasattr(cls, "format"):
                args = cls.format.unpack_from(data)
            else:
                return cls()
        except struct.error:
            raise ProtocolError()
        return cls(*args)


@dataclass
class RequestHeader(ClientRequest):
    format: ClassVar[struct.Struct] = struct.Struct("<16sBHi")
    client_id: bytes
    version: int
    code: int
    payload_size: int
    size: int = format.size

    def pack(self) -> bytes:
        return generate_pack(self, ["client_id", "version", "code", "payload_size"])


@dataclass
class SignupRequest(ClientRequest):
    format: ClassVar[struct.Struct] = struct.Struct("<255s160s")
    name: bytes
    pub_key: bytes
    size: int = format.size

    def pack(self) -> bytes:
        return generate_pack(self, ["name", "pub_key"])


@dataclass
class UserList(ClientRequest):
    size: int = 0


@dataclass
class UserPublicKeyRequest(ClientRequest):
    format: ClassVar[struct.Struct] = struct.Struct("<16s")
    target_client_id: bytes
    size: int = format.size

    def pack(self) -> bytes:
        return generate_pack(self, ["target_client_id"])

@dataclass
class SendMessageRequest(ClientRequest):
    format: ClassVar[struct.Struct] = struct.Struct("<16sBi")
    target_client_id: bytes
    message_type: int
    content_size: int
    message_content: bytes

    @classmethod
    def unpack(cls, data: bytes):
        header = data[: cls.format.size]
        payload = data[cls.format.size:]
        try:
            args = list(cls.format.unpack_from(header))
        except struct.error:
            raise ProtocolError()
        args.append(payload)
        return cls(*args)


@dataclass
class GetAvailableMessages(ClientRequest):
    size: int = 0
