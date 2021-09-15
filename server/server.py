import logging
import socketserver
import server_protocol
from server_logic import ServerLogic


logger = logging.getLogger(__name__)


class RequestHandler(socketserver.BaseRequestHandler):
    def _read_until_size_met(self, size: int) -> bytes:
        data_read = b""
        while bytes_left_to_read := size - len(data_read):
            data_read += self.request.recv(bytes_left_to_read)
        return data_read

    def _handle_request(self, header_obj: server_protocol.RequestHeader) -> None:
        payload = self._read_until_size_met(header_obj.payload_size)
        if not isinstance(self.server, Server):
            raise RuntimeError(
                "This RequestHandler cannot be used with a different server"
            )
        self.request.send(
            self.server.server_logic.dispatch_payload(header_obj, payload)
        )

    def handle(self) -> None:
        request_header = self._read_until_size_met(server_protocol.RequestHeader.size)
        try:
            header_obj = server_protocol.RequestHeader.unpack(request_header)
            self._handle_request(header_obj)
        except server_protocol.ProtocolError:
            logger.exception(
                f"Caught an exception while handling header for {self.client_address}"
            )


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, bind_and_activate=True) -> None:
        super().__init__(
            server_address,
            RequestHandlerClass=RequestHandler,
            bind_and_activate=bind_and_activate,
        )
        self.server_logic = ServerLogic()
