#pragma once
#include <list>


const int CLIENT_VERSIION = 1; 

class ProtocolException : public std::exception {
};


enum RequestType {
	SIGNUP_REQUEST = 1000,
	USER_LIST_REQUEST = 1001,
	USER_PUBLIC_KEY_REQUEST = 1002,
	MESSAGE_USER_REQUEST = 1003,
	QUEUED_MESSAGES_REQUEST = 1004,
};

enum ResponseType {
	SIGNUP_SUCCESS_RESPONSE = 2000,
	USER_LIST_RESPONSE = 2001,
	USER_PUBLIC_KEY_RESPONSE = 2002,
	MESSAGE_SENT_TO_USER_RESPONSE = 2003,
	QUEUED_MESSAGES_RESPONSE = 2004,
	SERVER_ERROR = 9000,
};



class RequestPayload {
protected:
	char* _data;
	int _data_size;

public:
	RequestPayload(char* data, int data_size);
	int data_size();
	char* get_data();
};

class PackedPayload {
public:
	char* _data;
	int _data_length;
	PackedPayload(char* data, int data_length);
};


class RequestHeader {
protected:
	std::array<char, 16> _client_id;
	char _version=CLIENT_VERSIION;
	unsigned short _code;
	unsigned int _payload_size;
	RequestPayload* _payload;
public:
	RequestHeader(std::array<char, 16> client_id, unsigned short code, RequestPayload* payload);
	PackedPayload* pack();
};


class SignupRequest : public RequestPayload {
public:
	SignupRequest(std::array<char, 255> name, std::array<char, 160> public_key);
	virtual ~SignupRequest();
};


class UserListRequest : public RequestPayload {
public:
	UserListRequest();
};

class UserPublicKeyRequest : public RequestPayload {
public:
	UserPublicKeyRequest(std::array<char, 16> client_id);
};


class MessageListRequest : public RequestPayload {
public:
	MessageListRequest();
};


class SendMessageRequest : public RequestPayload {
public:
	SendMessageRequest(std::array<char, 16> client_id, uint8_t type, int content_size, char* message_content);
};


class ResponsePayload {
public:
	virtual ~ResponsePayload() {};
};


class ResponseHeader {
protected:
	uint8_t _server_version;
	unsigned short _code;
	unsigned int _payload_size;
public:
	ResponseHeader(char data[7]);
	int GetPyaloadSize();
	short GetResponseCode();
};


class SignupSuccessResponse : public virtual ResponsePayload {
private:
	std::array<char, 16> _client_id;
public:
	SignupSuccessResponse(char* data, int data_size);
	std::array<char, 16> GetClientID();
};

class UserListResponseRecord {
private:
	std::array<char, 16> _client_id;
	std::array<char, 255> _client_name;
public:
	UserListResponseRecord(char* data);
	std::array<char, 16> GetClientID();
	std::array<char, 255> GetClientName();
};

class UserListResponse : public virtual ResponsePayload {
public:
	std::list<UserListResponseRecord*> users;
	UserListResponse(char* data, int data_size);
	virtual ~UserListResponse();
};

class UserPublicKeyResponse : public virtual ResponsePayload {
private:
	std::array<char, 16> _client_id;
	std::array<char, 160> _public_key;
public:
	UserPublicKeyResponse(char* data, int data_size);
	std::array<char, 16> GetClientID();
	std::array<char, 160> GetPublicKey();
};


class MessageSentResponse : public virtual ResponsePayload {
private:
	std::array<char, 16> _client_id;
	int _message_id;
public:
	MessageSentResponse(char* data, int data_size);
	int GetMessageID();
};


class AwaitingMessageRecord {
private:
	std::array<char, 16> _client_id;
	int _message_id;
	uint8_t _message_type;
	int _message_size;
	char* _content;
public:
	AwaitingMessageRecord(char* data, int data_size);
	virtual ~AwaitingMessageRecord();
	std::array<char, 16> GetSender();
	int GetMessageID();
	char* GetMessageContent();
	int GetMessageSize();
	uint8_t GetMessageType();
};


class AwaitingMessagesResponse : public virtual ResponsePayload {
public:
	std::list<AwaitingMessageRecord*> messages;
	AwaitingMessagesResponse(char* data, int data_size);
	virtual ~AwaitingMessagesResponse();
};


class ServerError : public virtual ResponsePayload {
public:
	ServerError();
};