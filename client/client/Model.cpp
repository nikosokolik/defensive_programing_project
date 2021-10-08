#include "Model.h"


Model::Model() {
	_controller = new Controller();
}

Model::~Model() {
	delete _controller;
}

void Model::Run() {
	UserCommand request;
	std::cout << "MessageU client at your service." << std::endl;
	while ((request = InputCommandFromUser()) != EXIT) {
		DispatchUserInput(request);
	}
	std::cout << "Closing client!" << std::endl;
}

std::string* Model::GetUserName() {
	std::string target_user_name;
	std::cout << "Please input target user name: ";
	std::cin >> target_user_name;
	return new std::string(target_user_name);
}

void Usage() {
	std::cout << std::endl;
	std::cout << REGISTER << ") Register" << std::endl;
	std::cout << REQUEST_CLIENT_LIST << ") Request client list" << std::endl;
	std::cout << REQUEST_PUBLIC_KEY << ") Request user's public key" << std::endl;
	std::cout << REQUEST_QUEUED_MESSAGES << ") Request waiting messages" << std::endl;
	std::cout << SEND_REGULAR_MESSAGE << ") Send a text message" << std::endl;
	std::cout << REQUEST_SYMMETIC_KEY << ") Send a request for symmetirc key" << std::endl;
	std::cout << SEND_SYMMETRIC_KEY << ") Respond with a symmetric key" << std::endl;
	std::cout << EXIT << ") Exit" << std::endl;
}

bool IsValidCommand(int input_command) {
	return ((input_command == REGISTER) ||
		(input_command == REQUEST_CLIENT_LIST) ||
		(input_command == REQUEST_PUBLIC_KEY) ||
		(input_command == REQUEST_QUEUED_MESSAGES) ||
		(input_command == SEND_REGULAR_MESSAGE) ||
		(input_command == REQUEST_SYMMETIC_KEY) ||
		(input_command == SEND_SYMMETRIC_KEY) ||
		(input_command == EXIT));
}

UserCommand FromString(std::string user_command) {
	int input_number;
	try {
		input_number = std::stoi(user_command);
		if (!IsValidCommand(input_number)) {
			std::cout << std::endl << "Invalid input! Please input one of:" << std::endl;
			return INVALID_INPUT;
		}
		return static_cast<UserCommand>(input_number);
	}
	catch (std::invalid_argument& e) {
		return INVALID_INPUT;
	}
	catch (std::out_of_range& e) {
		return INVALID_INPUT;
	}
}

UserCommand Model::InputCommandFromUser() {
	std::string user_command;
	Usage();
	std::cin >> user_command;
	UserCommand input_command = FromString(user_command);
	while (input_command == INVALID_INPUT) {
		Usage();
		std::cin >> user_command;
		input_command = FromString(user_command);
	}
	return input_command;
}

void Model::DispatchUserInput(UserCommand input) {
	std::string message;
	std::array<char, 255> target_user_name_array;
	if ((input == REQUEST_PUBLIC_KEY) || (input == SEND_REGULAR_MESSAGE) || (input == REQUEST_SYMMETIC_KEY) || (input == SEND_SYMMETRIC_KEY)) {
		target_user_name_array.fill(0);
		std::string* target_user_name = GetUserName();
		std::copy_n(std::begin(*target_user_name), target_user_name->size(), target_user_name_array.begin());
		delete target_user_name;
	}
	switch (input)
	{
	case REGISTER:
		_controller->Register();
		break;
	case REQUEST_CLIENT_LIST:
		_controller->UpdateUserList();
		break;
	case REQUEST_PUBLIC_KEY:
		_controller->RequestPublicKey(target_user_name_array);
		break;
	case REQUEST_QUEUED_MESSAGES:
		_controller->RequestMessages();
		break;
	case SEND_REGULAR_MESSAGE:
		std::cout << "Input message for " << target_user_name_array.data() << " :";
		std::cin >> message;
		_controller->SendMessageToUser(target_user_name_array, (char*)message.c_str(), message.length());
		break;
	case REQUEST_SYMMETIC_KEY:
		_controller->RequestSymmetricKeyFromUser(target_user_name_array);
		break;
	case SEND_SYMMETRIC_KEY:
		_controller->GenerateSymmetricKeyForUser(target_user_name_array);
		break;
	case EXIT:
	default:
		std::cout << "Closing MessageU client." << std::endl;
		exit(0);
		break;
	}
}