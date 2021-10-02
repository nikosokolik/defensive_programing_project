#include <iostream>
#include "Dispatcher.h"



Dispatcher::Dispatcher(const char* target_host, int target_port, RequestHeader* request) {
	try {
		boost::asio::io_service io_service;
		boost::asio::ip::tcp::socket sock = boost::asio::ip::tcp::socket(io_service);
		boost::asio::ip::tcp::resolver resolver(io_service);
		boost::asio::connect(sock, resolver.resolve(target_host, std::to_string(target_port)));
		_result = this->_dispatch(request, &sock);
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;
		throw NetworkException();
	}
}


Dispatcher::~Dispatcher() {
	if (_result) {
		delete _result;
	}
}


char* Dispatcher::_ReadUntilMeetsLength(boost::asio::ip::tcp::socket* sock, int expected_length) {
	/* User must free returned buffer! */
	if (expected_length <= 0) { return NULL; }
	char* result = (char*)malloc(expected_length * sizeof(char));
	if (!result) {
		throw NetworkException();
	}
	int bytes_read = 0;
	while (bytes_read < expected_length) {
		bytes_read += boost::asio::read(*sock, boost::asio::buffer(result + bytes_read, expected_length - bytes_read));
	}
	return result;
	}

ResponseHeader* Dispatcher::_ReadHeader(boost::asio::ip::tcp::socket* sock) {
	/* user must free return value */
	char* header_data = this->_ReadUntilMeetsLength(sock, 7);
	if (!header_data) {
		throw new NetworkException();
	}
	ResponseHeader* result = new ResponseHeader(header_data);
	free(header_data);
	return result;
}

ResponsePayload* Dispatcher::_ParseResponse(ResponseHeader* header, char* data_read) {
	int buffer_size = header->GetPyaloadSize();
	switch (header->GetResponseCode()) {
	case SIGNUP_SUCCESS_RESPONSE:
		return new SignupSuccessResponse(data_read, buffer_size);
	case USER_LIST_RESPONSE:
		return new UserListResponse(data_read, buffer_size);
	case USER_PUBLIC_KEY_RESPONSE:
		return new UserPublicKeyResponse(data_read, buffer_size);
	case MESSAGE_SENT_TO_USER_RESPONSE:
		return new MessageSentResponse(data_read, buffer_size);
	case QUEUED_MESSAGES_RESPONSE:
		return new AwaitingMessagesResponse(data_read, buffer_size);
	case SERVER_ERROR:
		return new ServerError();
	default:
		std::cerr << "Server responded with code: " << header->GetResponseCode() << std::endl;
		return new ServerError();
	}
}

ResponsePayload* Dispatcher::_dispatch(RequestHeader* request, boost::asio::ip::tcp::socket* sock) {
	PackedPayload* data = request->pack();
	sock->send(boost::asio::buffer(data->_data, data->_data_length));
	ResponseHeader* header = this->_ReadHeader(sock);
	char* payload_data = this->_ReadUntilMeetsLength(sock, header->GetPyaloadSize());
	ResponsePayload* return_value = this->_ParseResponse(header, payload_data);
	if (payload_data) {
		free(payload_data);
	}
	return return_value;
}

ResponsePayload* Dispatcher::GetResult() {
	return _result;
}