import abc
import enum
import struct
from server_protocol.utils import generate_pack
from dataclasses import dataclass
from typing import ClassVar, List, Callable


class ResponseCode(enum.Enum):
    SIGNUP_SUCCESS = 2000
    USER_LIST = 2001
    USER_PUBKEY = 2002
    MESSAGE_SENT = 2003
    MESSAGES = 2004
    ERROR = 9000


SERVER_VERSION = 2


class ServerResponse(abc.ABC):
    """
    A class that represents a server response. Should not be used directly but rather inherited from.
    """

    def __init__(self, payload: bytes, version: int, code: ResponseCode):
        self._header_format: struct.Struct = struct.Struct("<BHi")
        self.payload = payload
        self.version: int = version
        self.code: ResponseCode = code
        self.payload_size: int = len(payload)

    def pack(self) -> bytes:
        return (
            self._header_format.pack(self.version, self.code, self.payload_size)
            + self.payload
        )

    def __str__(self):
        return f"<{self.__class__.__name__} - {self.__dict__}>"


class SignupSuccess(ServerResponse):
    def __init__(self, client_id: bytes):
        super().__init__(
            payload=self._pack_payload(client_id),
            version=SERVER_VERSION,
            code=ResponseCode.SIGNUP_SUCCESS,
        )

    @staticmethod
    def _pack_payload(client_id: bytes) -> bytes:
        payload_format: struct.Struct = struct.Struct("<16s")
        return payload_format.pack(client_id)


@dataclass
class ClientRecord:
    """
    A class that represents a client in the client list response
    """

    format: ClassVar[struct.Struct] = struct.Struct("<16s255s")
    client_id: bytes
    client_name: bytes
    pack: Callable[[], bytes] = generate_pack(["client_id", "client_name"])


class UserListResponse(ServerResponse):
    def __init__(self, clients: List[ClientRecord]):
        super().__init__(
            version=SERVER_VERSION,
            payload=self._pack_payload(clients),
            code=ResponseCode.USER_LIST,
        )

    @staticmethod
    def _pack_payload(clients: List[ClientRecord]):
        return b"".join([client.pack() for client in clients])


class UserPublicKey(ServerResponse):
    def __init__(self, client_id: bytes, public_key: bytes):
        super().__init__(
            payload=UserPublicKey._pack_payload(client_id, public_key),
            version=SERVER_VERSION,
            code=ResponseCode.USER_PUBKEY,
        )

    @staticmethod
    def _pack_payload(client_id: bytes, public_key: bytes) -> bytes:
        payload_format: struct.Struct = struct.Struct("<16s160s")
        return payload_format.pack(client_id, public_key)


class MessageSent(ServerResponse):
    def __init__(self, client_id: bytes, message_id: int):
        super().__init__(
            MessageSent._pack_payload(client_id, message_id),
            version=SERVER_VERSION,
            code=ResponseCode.MESSAGE_SENT,
        )

    @staticmethod
    def _pack_payload(client_id: bytes, message_id: int):
        payload_format: struct.Struct = struct.Struct("<16si")
        return payload_format.pack(client_id, message_id)


class MessageRecord:
    """
    A class that represents a message in the message list response
    """

    def __init__(self, sender_client_id: bytes, message_id: int, message: bytes):
        self.sender_client_id: bytes = sender_client_id
        self.message_id: int = message_id
        self.message: bytes = message

    def pack(self) -> bytes:
        payload_format: struct.Struct = struct.Struct("<16siBi")
        message_size: int = len(self.message)
        return (
            payload_format.pack(self.sender_client_id, self.message_id, message_size)
            + self.message
        )


class MessageList(ServerResponse):
    def __init__(self, message_list: List[MessageRecord]):
        super().__init__(
            version=SERVER_VERSION,
            payload=MessageList._pack_payload(message_list),
            code=ResponseCode.MESSAGES,
        )

    @staticmethod
    def _pack_payload(messages: List[MessageRecord]):
        return b"".join([message.pack() for message in messages])


class ErrorResponse(ServerResponse):
    def __init__(self):
        super().__init__(payload=b"", version=SERVER_VERSION, code=ResponseCode.ERROR)
