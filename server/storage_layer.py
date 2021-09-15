import abc
import uuid
import datetime
from dataclasses import dataclass
from typing import Tuple, Any, List
from server_protocol import SignupRequest


class StorageLayerException(Exception):
    ...


class StorageLayer(abc.ABC):
    @abc.abstractmethod
    def get_user_by_id(
        self, identifier: str
    ) -> Tuple[uuid.UUID, str, str, datetime.datetime]:
        """
        Retur
        :param identifier: user_id
        :return: user_id, name, public_key and last_seen_time
        """
        ...

    @abc.abstractmethod
    def check_if_user_exists(self, identifier: str) -> bool:
        ...

    @abc.abstractmethod
    def create_new_user(self, name: str, public_key: str) -> str:
        ...

    @abc.abstractmethod
    def get_message_list_for_user(
        self, identifier: str
    ) -> List[Tuple[str, str, str, int, bytes]]:
        ...


@dataclass
class Message:
    message_id: str
    source: uuid.UUID
    destination: uuid.UUID
    message_type: int
    content: bytes


class User:
    def __init__(
        self,
        identifier: uuid.UUID,
        name: str,
        public_key: str,
        last_seen: datetime.datetime,
    ) -> None:
        self._id = identifier
        self._name = name
        self._public_key = public_key
        self._last_seen = last_seen

    @staticmethod
    def get_user_by_id(storage_layer: StorageLayer, user_id: str) -> Any:
        if not storage_layer.check_if_user_exists(user_id):
            raise StorageLayerException(f"User {user_id} does not exist!")
        return User(*storage_layer.get_user_by_id(user_id))

    @staticmethod
    def create_new_user(storage_layer: StorageLayer, request: SignupRequest) -> Any:
        new_id = storage_layer.create_new_user(
            name=request.name.decode(), public_key=request.pub_key.decode()
        )
        return User.get_user_by_id(storage_layer, new_id)

    def get_all_messages(self, storage_layer: StorageLayer) -> List[Message]:
        messages: List[Message] = []
        for (
            message_id,
            source,
            destination,
            message_type,
            content,
        ) in storage_layer.get_message_list_for_user(self.id):
            messages.append(
                Message(
                    message_id,
                    uuid.UUID(hex=str(source)),
                    uuid.UUID(hex=str(destination)),
                    message_type,
                    content,
                )
            )
        return messages

    @property
    def id(self) -> str:
        return str(self._id)

    @property
    def name(self) -> str:
        return self._name

    @property
    def public_key(self) -> str:
        return self._name

    @property
    def last_seen(self) -> str:
        return self._name
