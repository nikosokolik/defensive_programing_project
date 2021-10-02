#include <iostream>
#include <array>
#include <stdlib.h>
#include <boost/asio.hpp>
#include "Protocol.h"


const char VERSION = 0x01;

unsigned short ShrotFromBuffer(char* buff) {
	return (unsigned short)((uint8_t)(buff[0]) | ((uint8_t)buff[1] << 8));
}

unsigned int IntFromBuffer(char* buff) {
	return (unsigned int)((uint8_t)(buff[0]) | (uint8_t)(buff[1]) << 8 | (uint8_t)(buff[2]) << 16 | (uint8_t)(buff[3]) << 24);
}


RequestPayload::RequestPayload(char* data, int data_size) {
	_data = data;
	_data_size = data_size;
}

int RequestPayload::data_size() {
	return _data_size;
}

char* RequestPayload::get_data() {
	return _data;
}

PackedPayload::PackedPayload(char* data, int data_length) {
	_data = data;
	_data_length = data_length;
}


RequestHeader::RequestHeader(std::array<char, 16> client_id, unsigned short code, RequestPayload* payload) {
	_client_id = client_id;
	_code = code;
	_payload = payload;
	_payload_size = payload->data_size();
}

PackedPayload* RequestHeader::pack() {
	int data_size = sizeof(_client_id) + sizeof(_version) + sizeof(_code) + sizeof(_payload_size) + _payload->data_size();
	char* data = (char*)malloc(sizeof(char)*data_size);
	if (!data) {
		throw ProtocolException();
	}
	char* index = data;
	memcpy(index, _client_id.data(), _client_id.size() * sizeof(char));
	index = index + _client_id.size() * sizeof(char);
	memcpy(index, &_version, sizeof(char));
	index = index + sizeof(char);
	memcpy(index, &_code, sizeof(unsigned short));
	index = index + sizeof(short);
	memcpy(index, &_payload_size, sizeof(int));
	index = index + sizeof(int);
	if (_payload_size) {
		memcpy(index, _payload->get_data(), _payload_size * sizeof(char));
	}
	PackedPayload* packed_payload = new PackedPayload(data, data_size);
	return packed_payload;
}

SignupRequest::SignupRequest(std::array<char, 255> name, std::array<char, 160> public_key) : RequestPayload(NULL, 0) {
	_data_size = name.size() + public_key.size();
	_data = (char*)malloc(sizeof(char) * _data_size);
	if (!_data) {
		throw ProtocolException();
	}
	memcpy(_data, name.data(), name.size() * sizeof(char));
	memcpy(_data + name.size() * sizeof(char), public_key.data(), public_key.size() * sizeof(char));
}

SignupRequest::~SignupRequest() {
	if (_data) {
		free(_data);
	}
}

UserListRequest::UserListRequest() : RequestPayload(NULL, 0) {}

UserPublicKeyRequest::UserPublicKeyRequest(std::array<char, 16> client_id) : RequestPayload(NULL, 0) {
	_data_size = client_id.size();
	_data = (char*)malloc(sizeof(char) * _data_size);
	if (!_data) {
		throw ProtocolException();
	}
	memcpy(_data, client_id.data(), client_id.size() * sizeof(char));
}

MessageListRequest::MessageListRequest() : RequestPayload(NULL, 0) {}


SendMessageRequest::SendMessageRequest(std::array<char, 16> client_id, uint8_t type, int content_size, char* message_content) : RequestPayload(NULL, 0) {
	_data_size = client_id.size() * sizeof(char) + sizeof(uint8_t) + sizeof(int) + content_size * sizeof(char);
	_data = (char*)malloc(sizeof(char) * _data_size);
	if (!_data) {
		throw ProtocolException();
	}
	char* index = _data;
	memcpy(index, client_id.data(), client_id.size() * sizeof(char));
	index = index + client_id.size() * sizeof(char);
	memcpy(index, &type, sizeof(uint8_t));
	index = index + sizeof(uint8_t);
	memcpy(index, &content_size, sizeof(int));
	index = index + sizeof(int);
	if (message_content) {
		memcpy(index, message_content, content_size * sizeof(char));
	}
}


ResponseHeader::ResponseHeader(char data[7]) {
	_server_version = (uint8_t)data[0];
	_code = ShrotFromBuffer(data + 1);
	_payload_size = IntFromBuffer(data + 3);
}


int ResponseHeader::GetPyaloadSize() { return _payload_size; }


short ResponseHeader::GetResponseCode() { return _code; }


SignupSuccessResponse::SignupSuccessResponse(char* data, int data_size) : ResponsePayload() {
	if (data_size != 16) {
		throw ProtocolException();
	}
	_client_id.fill(0);
	std::copy_n(data, 16, _client_id.begin());
}


std::array<char, 16> SignupSuccessResponse::GetClientID() {
	return _client_id;
}


UserListResponseRecord::UserListResponseRecord(char* data) {
	_client_id.fill(0);
	_client_name.fill(0);
	std::copy_n(data, 16, _client_id.begin());
	std::copy_n(data + 16 , 255, _client_name.begin());
}


std::array<char, 16> UserListResponseRecord::GetClientID() {
	return _client_id;
}

std::array<char, 255> UserListResponseRecord::GetClientName() {
	return _client_name;
}


UserListResponse::UserListResponse(char* data, int data_size) : ResponsePayload() {
	int user_count = data_size / (16 + 255);
	if (data_size % (16 + 255)) { // Make sure that the data devides exactly by (16+255)
		throw ProtocolException();
	}
	for (int i = 0; i < user_count; i++) {
		users.push_back(new UserListResponseRecord(data + i * (16 + 255)));
	}
}


UserListResponse::~UserListResponse() {
	for (auto const& user : users) {
		delete user;
	}
}


UserPublicKeyResponse::UserPublicKeyResponse(char* data, int data_size) : ResponsePayload() {
	if (data_size != 176) {
		throw ProtocolException();
	}
	_client_id.fill(0);
	_public_key.fill(0);
	std::copy_n(data, 16, _client_id.begin());
	std::copy_n(data + 16, 160, _public_key.begin());
}


std::array<char, 16> UserPublicKeyResponse::GetClientID() {
	return _client_id;
}


std::array<char, 160> UserPublicKeyResponse::GetPublicKey() {
	return _public_key;
}


MessageSentResponse::MessageSentResponse(char* data, int data_size) : ResponsePayload() {
	if (data_size != 20) {
		throw ProtocolException();
	}
	_client_id.fill(0);
	std::copy_n(data, 16, _client_id.begin());
	_message_id = IntFromBuffer(data + 16);
}


int MessageSentResponse::GetMessageID() {
	return _message_id;
}


AwaitingMessageRecord::AwaitingMessageRecord(char* data, int data_size) {
	if (data_size < 25) {
		throw ProtocolException();
	}
	_client_id.fill(0);
	std::copy_n(data, 16, _client_id.begin());
	_message_id = IntFromBuffer(data + 16);
	_message_type = (uint8_t)(data[20]);
	_message_size = IntFromBuffer(data + 21);
	if (data_size < 25 + _message_size) {
		throw ProtocolException();
	}
	_content = (char*)malloc(sizeof(char) * _message_size);
	if (!_content) {
		throw ProtocolException();
	}
	memcpy(_content, data + 25, _message_size);
}

AwaitingMessageRecord::~AwaitingMessageRecord() {
	if (_content) {
		free(_content);
	}
}


std::array<char, 16> AwaitingMessageRecord::GetSender() {
	return _client_id;
}


int AwaitingMessageRecord::GetMessageID() {
	return _message_id;
}


char* AwaitingMessageRecord::GetMessageContent() {
	return _content;
}


int AwaitingMessageRecord::GetMessageSize() {
	return _message_size;
}


uint8_t AwaitingMessageRecord::GetMessageType() {
	return _message_type;
}


AwaitingMessagesResponse::AwaitingMessagesResponse(char* data, int data_size) : ResponsePayload() {
	AwaitingMessageRecord* current_message;
	while (data_size > 0) {
		current_message = new AwaitingMessageRecord(data, data_size);
		data_size = data_size - current_message->GetMessageSize();
		data = data + current_message->GetMessageSize();
		messages.push_back(current_message);
	}
}


AwaitingMessagesResponse::~AwaitingMessagesResponse() {
	for (auto const& message : messages) {
		delete message;
	}
}


ServerError::ServerError() : ResponsePayload() {}