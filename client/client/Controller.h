#pragma once
#include <list>
#include <array>
#include <string>
#include "User.h"
#include "KeyManager.h"


const std::string SERVER_INFO_FILENAME = "\\server.info";
const std::string USER_INFO_FILENAME = "\\me.info";

class ControllerException : public std::exception {
};
class UserNotFoundException : public std::exception {
};

enum MessageTypes
{
	SYMMETRIC_KEY_REQUEST = 1,
	SYMMETRIC_KEY_RESPONSE = 2,
	REGULAR_MESSAGE_REQUEST = 3
};

class Controller {
private:
	std::string _server_host;
	int _server_port;
	std::map<std::array<char, 16>, User*>* _users;
	std::array<char, 16> _user_id;
	std::array<char, 255> _user_name;
	bool _is_registered = false;
	KeyManager* _key_manager;
	void _LoadServerInfo();
	void _LoadUserInfo();
	void _DumpUserInfo();
	std::array<char, 16> _GetUserIDByName(std::array<char, 255> user_name);
	bool _GenerateNewKeyForUser(std::array<char, 16> target_user_id);
public:
	Controller();
	virtual ~Controller();
	void Register();
	void UpdateUserList();
	void RequestPublicKey(std::array<char, 255> user_name);
	void RequestMessages();
	void GenerateSymmetricKeyForUser(std::array<char, 255> user_name);
	void SendMessageToUser(std::array<char, 255> user_name, char* message_content, int message_size);
	void RequestSymmetricKeyFromUser(std::array<char, 255> user_name);
};
