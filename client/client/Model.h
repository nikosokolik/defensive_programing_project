#pragma once
#include "Controller.h"


enum UserCommand {
	EXIT = 0,
	REGISTER = 10,
	REQUEST_CLIENT_LIST = 20,
	REQUEST_PUBLIC_KEY = 30,
	REQUEST_QUEUED_MESSAGES = 40,
	SEND_REGULAR_MESSAGE = 50,
	REQUEST_SYMMETIC_KEY = 51,
	SEND_SYMMETRIC_KEY = 52,
	INVALID_INPUT = -1,
};


class Model {
private:
	Controller* _controller;
	std::string* GetUserName();
	UserCommand InputCommandFromUser();
	void DispatchUserInput(UserCommand input);
public:
	Model();
	~Model();
	void Run();
};
