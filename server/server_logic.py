import uuid
import logging
import pathlib
import server_protocol
from storage.database_storage import DBStorage
from typing import Dict, TypeVar, Any, Callable, Type, List
from storage.storage_layer import StorageLayer, StorageLayerException, User, UserList


T = TypeVar("T", bound=Callable[..., Any])
logger = logging.getLogger(__name__)
DATABASE_PATH = pathlib.Path(__file__).parent.joinpath("server.db")


def safe_call_decorator(func: T) -> T:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except (SecurityException, ServerLogicalException) as e:
            logger.error(f"Error responding to client! {type(e)} - {e}")
            return server_protocol.ErrorResponse()
        except Exception:
            logger.exception("Caught an exception while responding to client!")
            return server_protocol.ErrorResponse()

    return wrapper  # type: ignore


class ServerLogicalException(Exception):
    ...


class SecurityException(Exception):
    ...


class DispatchManager:
    AUTH_REQUIRED_REQUESTS: List[server_protocol.RequestCode] = [
        server_protocol.RequestCode.USER_LIST,
        server_protocol.RequestCode.USER_PUBKEY,
        server_protocol.RequestCode.MESSAGE_REQUEST,
        server_protocol.RequestCode.READ_MESSAGES,
    ]
    _dispatch_request_types_dict: Dict[
        server_protocol.RequestCode, Type[server_protocol.ClientRequest]
    ] = {
        server_protocol.RequestCode.SIGNUP: server_protocol.SignupRequest,
        server_protocol.RequestCode.USER_LIST: server_protocol.UserList,
        server_protocol.RequestCode.USER_PUBKEY: server_protocol.UserPublicKeyRequest,
        server_protocol.RequestCode.MESSAGE_REQUEST: server_protocol.SendMessageRequest,
        server_protocol.RequestCode.READ_MESSAGES: server_protocol.GetAvailableMessages,
    }

    def __init__(self, storage: StorageLayer):
        self._storage: StorageLayer = storage
        self._dispatch_request_funcs_dict: Dict[
            Type[server_protocol.ClientRequest],
            Callable[
                [server_protocol.ClientRequest, str], server_protocol.ServerResponse
            ],
        ] = {
            server_protocol.SignupRequest: self._dispatch_signup,
            server_protocol.UserList: self._dispatch_user_list,
            server_protocol.UserPublicKeyRequest: self._dispatch_user_public_key_request,
            server_protocol.SendMessageRequest: self._dispatch_send_message,
            server_protocol.GetAvailableMessages: self._dispatch_get_messages,
        }

    @staticmethod
    def _payload_size_aligns(expected_size: int, payload: bytes) -> bool:
        return len(payload) == expected_size

    @safe_call_decorator
    def _dispatch_signup(
        self, request: server_protocol.SignupRequest, client_id: str
    ) -> server_protocol.SignupSuccess:
        user = User.create_new_user(self._storage, request)
        return server_protocol.SignupSuccess(user.id.encode())

    @safe_call_decorator
    def _dispatch_user_list(
        self, request: server_protocol.UserList, client_id: str
    ) -> server_protocol.UserListResponse:
        clients: List[server_protocol.ClientRecord] = []
        for client in UserList.get_user_list(self._storage, client_id):
            clients.append(
                server_protocol.ClientRecord(uuid.UUID(client.id).bytes, client.name.encode())
            )
        return server_protocol.UserListResponse(clients)

    @safe_call_decorator
    def _dispatch_user_public_key_request(
        self, request: server_protocol.UserPublicKeyRequest, client_id: str
    ) -> server_protocol.UserPublicKey:
        user = User.get_user_by_id(self._storage, request.target_client_id.hex())
        return server_protocol.UserPublicKey(user.id.encode(), user.public_key)

    @safe_call_decorator
    def _dispatch_send_message(
        self, request: server_protocol.SendMessageRequest, client_id: str
    ) -> server_protocol.MessageSent:
        user = User.get_user_by_id(self._storage, request.target_client_id.decode())
        message_id = user.send_message(
            self._storage, client_id, request.message_type, request.message_content
        )
        return server_protocol.MessageSent(user.id, message_id)

    @safe_call_decorator
    def _dispatch_get_messages(
        self, request: server_protocol.GetAvailableMessages, client_id: str
    ) -> server_protocol.MessageList:
        user = User.get_user_by_id(self._storage, client_id)
        messages = user.get_all_messages(self._storage)
        message_list: List[server_protocol.MessageRecord] = []
        for message in messages:
            message_list.append(
                server_protocol.MessageRecord(
                    message.sourcem, message.message_id, message.content
                )
            )
        return server_protocol.MessageList(message_list)

    def _check_user_valid(self, user_id: bytes) -> bool:
        try:
            User.get_user_by_id(self._storage, user_id.decode())
            return True
        except StorageLayerException:
            return False

    def _dispatch(
        self, payload: server_protocol.RequestHeader, client_id: str
    ) -> server_protocol.ServerResponse:
        if type(payload) not in self._dispatch_request_funcs_dict.keys():
            raise ServerLogicalException("This line should never be reached")
        return self._dispatch_request_funcs_dict[type(payload)](payload, client_id)

    @safe_call_decorator
    def dispatch_payload(
        self, request_header: server_protocol.RequestHeader, payload: bytes
    ) -> server_protocol.ServerResponse:
        if (
            request_header.code
            not in [item.value for item in server_protocol.RequestCode]
            or server_protocol.RequestCode(request_header.code)
            not in self._dispatch_request_types_dict.keys()
        ):
            raise ServerLogicalException("Unexpected request code!")
        request = self._dispatch_request_types_dict[
            server_protocol.RequestCode(request_header.code)
        ].unpack(payload)
        logger.debug("Got request {!r}".format(payload))
        if request_header.code in DispatchManager.AUTH_REQUIRED_REQUESTS:
            if self._check_user_valid(request_header.client_id):
                self._storage.update_user_last_seen(request_header.client_id)
            else:
                raise SecurityException(
                    "User with id {!r} does not exit!".format(request_header.client_id)
                )
        return self._dispatch(request, request_header.client_id.decode())


class ServerLogic:
    def __init__(self) -> None:
        self._storage = DBStorage(str(DATABASE_PATH))
        self._dispatch_manager: DispatchManager = DispatchManager(self._storage)

    def dispatch_payload(
        self, request_header: server_protocol.RequestHeader, payload: bytes
    ) -> bytes:
        return self._dispatch_manager.dispatch_payload(request_header, payload).pack()

    def close_connection(self) -> None:
        self._storage.close_connection()
