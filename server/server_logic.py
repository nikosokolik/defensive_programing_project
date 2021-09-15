import logging
import server_protocol
from database_storage import DBStorage
from storage_layer import StorageLayer, StorageLayerException, User
from typing import Dict, TypeVar, Any, Callable, Type, List


T = TypeVar("T", bound=Callable[..., Any])
logger = logging.getLogger(__name__)


def safe_call_decorator(func: T) -> T:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except (SecurityException, ServerLogicalException) as e:
            logger.error(f"Error responding to client! {type(e)} - {e}")
            return server_protocol.ProtocolError()
        except Exception:
            logger.exception("Caught an exception while responding to client!")
            return server_protocol.ProtocolError()

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
            Callable[[server_protocol.RequestHeader], server_protocol.ServerResponse],
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
        self, request: server_protocol.SignupRequest
    ) -> server_protocol.SignupSuccess:
        user = User.create_new_user(self._storage, request)
        return server_protocol.SignupSuccess(user.id.decode())

    @safe_call_decorator
    def _dispatch_user_list(
        self, request: server_protocol.UserList
    ) -> server_protocol.UserListResponse:
        pass

    @safe_call_decorator
    def _dispatch_user_public_key_request(
        self, request: server_protocol.UserPublicKeyRequest
    ) -> server_protocol.UserPublicKey:
        user = User.get_user_by_id(self._storage, request.target_client_id.decode())
        return server_protocol.UserPublicKey(user.id.encode(), user.public_key.encode())

    @safe_call_decorator
    def _dispatch_send_message(
        self, request: server_protocol.SendMessageRequest
    ) -> server_protocol.MessageSent:
        pass

    @safe_call_decorator
    def _dispatch_get_messages(
        self, request: server_protocol.GetAvailableMessages
    ) -> server_protocol.MessageList:
        pass

    def _check_user_valid(self, user_id: bytes) -> bool:
        try:
            User.get_user_by_id(self._storage, user_id.decode())
            return True
        except StorageLayerException:
            return False

    def _dispatch(
        self,
        payload: server_protocol.RequestHeader,
    ) -> server_protocol.ServerResponse:
        if not type(payload) not in self._dispatch_request_funcs_dict.keys():
            raise ServerLogicalException("This line should never be reached")
        return self._dispatch_request_funcs_dict[type(payload)](payload)

    @safe_call_decorator
    def dispatch_payload(
        self, request_header: server_protocol.RequestHeader, payload: bytes
    ) -> server_protocol.ServerResponse:
        if (
            request_header.code not in server_protocol.RequestCode
            or request_header.code not in self._dispatch_request_types_dict
        ):
            raise ServerLogicalException("Unexpected request code!")
        request = self._dispatch_request_types_dict[
            server_protocol.RequestCode(request_header)
        ].unpack(payload)
        logger.debug("Got request {!r}".format(payload))
        if (
            request_header.code in DispatchManager.AUTH_REQUIRED_REQUESTS
            and not self._check_user_valid(request_header.client_id)
        ):
            raise SecurityException(
                "User with id {!r} does not exit!".format(request_header.client_id)
            )
        return self._dispatch(request)


class ServerLogic:
    def __init__(self) -> None:
        self._storage = DBStorage()
        self._dispatch_manager: DispatchManager = DispatchManager(self._storage)

    def dispatch_payload(
        self, request_header: server_protocol.RequestHeader, payload: bytes
    ) -> bytes:
        return self._dispatch_manager.dispatch_payload(request_header, payload).pack()
