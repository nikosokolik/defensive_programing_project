import logging
import server_protocol
from typing import Dict, TypeVar, Any, Callable


T = TypeVar("T", bound=Callable[..., Any])
logger = logging.getLogger(__name__)


def safe_call_decorator(func: T) -> T:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception:
            logger.exception("Caught an exception while responding to client")
            return server_protocol.ProtocolError()

    return wrapper  # type: ignore


class ServerLogicalException(Exception):
    ...


class ServerLogic:
    _dispatch_dict: Dict[server_protocol.RequestCode, server_protocol.RequestHeader] = {
        server_protocol.RequestCode.SIGNUP: server_protocol.SignupRequest,
        server_protocol.RequestCode.USER_LIST: server_protocol.UserList,
        server_protocol.RequestCode.USER_PUBKEY: server_protocol.UserPublicKeyRequest,
        server_protocol.RequestCode.MESSAGE_REQUEST: server_protocol.SendMessageRequest,
        server_protocol.RequestCode.READ_MESSAGES: server_protocol.GetAvailableMessages,
    }

    @staticmethod
    def _payload_size_aligns(expected_size: int, payload: bytes) -> bool:
        return len(payload) == expected_size

    @safe_call_decorator
    def _dispatch_signup(
        self, request: server_protocol.SignupRequest
    ) -> server_protocol.SignupSuccess:
        pass

    @safe_call_decorator
    def _dispatch_user_list(
        self, request: server_protocol.UserList
    ) -> server_protocol.UserListResponse:
        pass

    @staticmethod
    def _dispatch(
        payload: server_protocol.RequestHeader,
    ) -> server_protocol.ServerResponse:
        if isinstance(payload, server_protocol.SignupRequest):
            return ServerLogic._dispatch_signup(payload)
        elif isinstance(payload, server_protocol.UserList):
            return ServerLogic._dispatch_user_list(payload)
        raise ServerLogicalException("This line should never be reached")

    @staticmethod
    @safe_call_decorator
    def dispatch_payload(
        request_header: server_protocol.RequestHeader, payload: bytes
    ) -> server_protocol.ServerResponse:
        if (
            request_header.code not in server_protocol.RequestCode
            or request_header.code not in ServerLogic._dispatch_dict
        ):
            raise ServerLogicalException("Unexpected request code!")
        payload = ServerLogic._dispatch_dict[
            server_protocol.RequestCode(request_header).code
        ].unpack(payload)
        logger.debug(f"Got request {payload}")
        return ServerLogic._dispatch(payload)
