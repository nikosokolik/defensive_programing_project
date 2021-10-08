#pragma once
#define BOOST_USE_WINDOWS_H
#include <boost/asio.hpp>
#include "Protocol.h"


class NetworkException : public std::exception {
};


class Dispatcher {
private:
	ResponsePayload* _result = NULL;

	char* _ReadUntilMeetsLength(boost::asio::ip::tcp::socket* sock, int expected_length);

	ResponseHeader* _ReadHeader(boost::asio::ip::tcp::socket* sock);

	ResponsePayload* _ParseResponse(ResponseHeader* header, char* data_read);

	ResponsePayload* _dispatch(RequestHeader* request, boost::asio::ip::tcp::socket* sock);

public:
	Dispatcher(const char* target_host, int target_port, RequestHeader* request);
	virtual ~Dispatcher();

	ResponsePayload* GetResult();
};