import uuid
import datetime
from typing import Tuple, List
from storage_layer import StorageLayer


class DBStorage(StorageLayer):
    def __init__(self):
        pass

    def get_user_by_id(
        self, identifier: str
    ) -> Tuple[uuid.UUID, str, str, datetime.datetime]:
        pass

    def check_if_user_exists(self, identifier: str) -> bool:
        pass

    def create_new_user(self, name: str, public_key: str) -> str:
        pass

    def get_message_list_for_user(self, identifier: str) -> List[Tuple[str, str, str, int, bytes]]:
        pass
