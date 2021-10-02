import uuid
import sqlite3
import datetime
from typing import Tuple, List, Callable, Any
from storage.storage_layer import StorageLayer, StorageLayerException


CREATE_TABLES = [
    """CREATE TABLE IF NOT EXISTS client (
    id VARCHAR(16) NOT NULL,
    name VARCHAR(250) NOT NULL,
    public_key VARBINARY(160) NOT NULL,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);""",
    """CREATE TABLE IF NOT EXISTS message (
    id int(4) NOT NULL PRIMARY KEY,
    source VARCHAR(16) NOT NULL,
    destination VARCHAR(16) NOT NULL,
    type INT(1) NOT NULL,
    content BLOB NOT NULL,
    FOREIGN KEY(source) REFERENCES client(id),
    FOREIGN KEY(destination) REFERENCES client(id)
);""",
]
SELECT_USER_BY_ID = """SELECT * FROM client WHERE id=?;"""
SELECT_USER_ID_LIST = """SELECT id FROM client WHERE id!=?;"""
INSERT_NEW_USER = """INSERT INTO client (id, name, public_key) VALUES (?,?,?);"""
SELECT_UNREAD_MESSAGES = """SELECT * FROM message WHERE destination=?;"""
UPDATE_LAST_SEEN = """UPDATE client SET last_seen=? WHERE id=?;"""
DELETE_MESSAGE = """DELETE FROM message WHERE id=?;"""
INSERT_NEW_MESSAGE = (
    """INSERT INTO message (source, destination, type, content) VALUES (?,?,?,?);"""
)
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def safe_sql_call(func: Callable[..., Any]) -> Callable[..., Any]:
    def _wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except sqlite3.Error as e:
            raise StorageLayerException(
                f"Caught an exception while executing query: {e}"
            )

    return _wrapper


class DBStorage(StorageLayer):
    def __init__(self, connection_string: str = ":memory:"):
        self.connection = sqlite3.connect(connection_string, check_same_thread=False)
        self._create_tables()

    def close_connection(self):
        self.connection.close()

    @safe_sql_call
    def _create_tables(self) -> None:
        with self.connection:
            self.connection.executescript("\n".join(CREATE_TABLES))

    @safe_sql_call
    def get_user_by_id(
        self, identifier: str
    ) -> Tuple[uuid.UUID, str, str, datetime.datetime]:
        identifier = identifier.replace("-", "")
        with self.connection:
            for user in self.connection.execute(SELECT_USER_BY_ID, (identifier,)):
                return (
                    uuid.UUID(hex=user[0]),
                    user[1],
                    user[2],
                    datetime.datetime.strptime(user[3], DATE_FORMAT),
                )
        raise StorageLayerException(f"User {identifier} not found!")

    @safe_sql_call
    def check_if_user_exists(self, identifier: str) -> bool:
        identifier = identifier.replace("-", "")
        try:
            self.get_user_by_id(identifier)
            return True
        except StorageLayerException:
            return False

    def _generate_available_user_id(self) -> str:
        identifier = str(uuid.uuid4())
        while self.check_if_user_exists(identifier):
            identifier = str(uuid.uuid4())
        return str(identifier).replace("-", "")

    @safe_sql_call
    def create_new_user(self, name: str, public_key: str) -> str:
        identifier = self._generate_available_user_id()
        with self.connection:
            self.connection.execute(INSERT_NEW_USER, (identifier, name, public_key))
        return identifier

    @safe_sql_call
    def get_user_id_list(self, id_to_ignore: str) -> List[str]:
        id_to_ignore = id_to_ignore.replace("-", "")
        with self.connection:
            return [
                line[0]
                for line in self.connection.execute(SELECT_USER_ID_LIST, (id_to_ignore,))
            ]

    @safe_sql_call
    def send_message(self, sender, receiver, message_type, content) -> str:
        cursor = self.connection.cursor()
        cursor.execute(INSERT_NEW_MESSAGE, (sender, receiver, message_type, content))
        new_message = cursor.lastrowid
        cursor.close()
        return new_message

    @safe_sql_call
    def get_message_list_for_user(
        self, identifier: str
    ) -> List[Tuple[str, str, str, int, bytes]]:
        identifier = identifier.replace("-", "")
        messages = []
        with self.connection:
            for row in self.connection.execute(SELECT_UNREAD_MESSAGES, identifier):
                messages.append(row)
                self.connection.execute(DELETE_MESSAGE, row[0])
        return messages

    def update_user_last_seen(self, user_id) -> None:
        last_seen = datetime.datetime.now().strftime(DATE_FORMAT)
        with self.connection:
            self.connection.execute(UPDATE_LAST_SEEN, (last_seen, user_id))
