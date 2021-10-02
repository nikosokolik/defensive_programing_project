#include <fstream>
#include <iostream>
#include <iomanip>
#include "Controller.h"
#include "Dispatcher.h"
#include "Protocol.h"
#include <Windows.h>
#include <algorithm>
#include <boost/dll/runtime_symbol_info.hpp>



std::string* getBinaryPath() {
	boost::filesystem::path p = boost::dll::program_location();
	return new std::string(p.string());
}


std::string getDirectoryPath(std::string filename) {
	std::string directory = ".";
	const size_t last_slash_idx = filename.rfind('\\');
	if (std::string::npos != last_slash_idx)
	{
		directory = filename.substr(0, last_slash_idx);
	}
	return directory;
}

int getHexFromChar(char* in) {
	unsigned int x;
	std::string a = { in[0], in[1] };
	return std::stoi(a, 0, 16);
}


std::string getServerInfoFilename() {
	std::string* filename = getBinaryPath();
	std::string directory = getDirectoryPath(*filename);
	delete filename;
	return directory + SERVER_INFO_FILENAME;
}


std::string getMeInfoFilename() {
	std::string* filename = getBinaryPath();
	std::string directory = getDirectoryPath(*filename);
	delete filename;
	return directory + USER_INFO_FILENAME;
}


void Controller::_LoadServerInfo() {
	std::string content;
	try {
		std::cout << getServerInfoFilename() << std::endl;
		std::ifstream ifs(getServerInfoFilename());
		if (ifs) {
			content = std::string((std::istreambuf_iterator<char>(ifs)),
				(std::istreambuf_iterator<char>()));
			ifs.close();
		}
		else {
			std::cerr << "Could not open server.info file - server.info file not found";
			throw ControllerException();
		}
	}
	catch (std::ifstream::failure e){
		std::cerr << "Could not open server.info file - " << e.what();
		throw ControllerException();
	}
	int index_of_split = content.find_first_of(":");
	_server_host = content.substr(0, index_of_split);
	_server_port = atoi(content.substr(index_of_split + 1, content.length()).c_str());
}

void Controller::_LoadUserInfo() {
	int i;
	std::ifstream ifs;
	std::string content;
	try {
		ifs = std::ifstream(getMeInfoFilename());
		if (!ifs) {
			_key_manager = new KeyManager();
			return;
		}
	}
	catch (std::ifstream::failure e) {
		std::cerr << "Could not open me.info file - " << e.what() << std::endl;
		_key_manager = new KeyManager();
		return;
	}
	try {
		content = std::string((std::istreambuf_iterator<char>(ifs)),
			(std::istreambuf_iterator<char>()));
		ifs.close();
	}
	catch (std::ifstream::failure e) {
		std::cerr << "Could not open me.info file - " << e.what() << std::endl;
		throw ControllerException();
	}
	try {
		int index_of_split = content.find_first_of("\n");
		/* If the user name is longer than 254, split at 254 (to also save one spot for \x00 */
		std::string user_name = content.substr(0, std::min(index_of_split, 254));
		_user_name.fill(0);
		_user_id.fill(0);
		std::copy_n(user_name.begin(), user_name.length(), std::begin(_user_name));
		std::string client_id = content.substr(index_of_split + 1, 32);
		for (i=0; i < _user_id.size(); i++) {
			_user_id[i] = (char)(getHexFromChar((char*)(client_id.data() + i * 2)));
		}
		_key_manager = new KeyManager(content.substr(index_of_split + 34, content.length() - index_of_split - 35));
		_is_registered = true;
	}
	catch (std::out_of_range e) {
		std::cerr << "Could not parse me.info file - " << e.what();
		throw ControllerException();
	}
}


void Controller::_DumpUserInfo() {
	std::ofstream ofs;
	try {
		ofs = std::ofstream(getMeInfoFilename(), std::ios::trunc);
		ofs << _user_name.data() << std::endl;
		for (int i = 0; i < _user_id.size(); ++i)
			ofs << std::hex << std::setfill('0') << std::setw(2) << _user_id[i];
		ofs << std::endl;
		std::string* key = _key_manager->GetEncodedPrivateKey();
		ofs << *key;
		delete key;
		ofs.close();
	} catch (std::ifstream::failure e) {
		std::cerr << "Could not open me.info file to write - " << e.what();
		return;
	}
}


void Controller::_GenerateNewKeyForUser(std::array<char, 16> target_user_id) {
	std::array<char, 128> key;
	auto s = _users->find(target_user_id);
	if (s == _users->end()) {
		std::cerr << "User is not in user list! check your input";
	}
	SymmetricKeyEncryptor sym_key = SymmetricKeyEncryptor();
	std::array<CryptoPP::byte, 128> key_source = *sym_key.GetKey();
	std::copy_n(key_source.begin(), key_source.size(), key.begin());
	s->second->UpdateSymmetricKey(key);
}


Controller::Controller() {
	_users = new std::map<std::array<char, 16>, User*>();
	this->_LoadServerInfo();
	this->_LoadUserInfo();
}


Controller::~Controller() {
	for (auto& user : *_users) {
		delete user.second;
	}
	delete _users;
	delete _key_manager;
}

std::string* ReadUserNameFromCIN() {
	std::string* user = new std::string();
	std::cout << "Please enter the user's name: ";
	std::getline(std::cin, *user);
	while (user->length() < 0 || user->length() > 254) {
		if (user->length() == 0) {
			std::cerr << "Empty user names are not supported!" << std::endl;
		}
		if (user->length() > 255) {
			std::cerr << "User name too long!";
		}
		std::cout << "Please enter the user's name: " << std::endl;
		std::getline(std::cin, *user);
	}
	return user;
}

bool IsServerError(ResponsePayload* response) {
	if (ServerError* s = dynamic_cast<ServerError*>(response)) {
		std::cerr << "Server responded with an error!" << std::endl;
		return true;
	}
	return false;
}

void Controller::Register() {
	if (_is_registered) {
		std::cerr << "User already registered!" << std::endl;
		return;
	}
	std::array<char, 160> public_key_array;
 	std::string* user_name = ReadUserNameFromCIN();
	std::string* public_key = _key_manager->GetPublicKey();
	_user_id.fill(0);
	_user_name.fill(0);
	std::copy_n(user_name->begin(), user_name->length(), _user_name.begin());
	std::copy_n(public_key->begin(), public_key->length(), public_key_array.begin());
	SignupRequest s = SignupRequest(_user_name, public_key_array);
	RequestHeader h = RequestHeader(_user_id, SIGNUP_REQUEST, &s);
	try {
		Dispatcher d = Dispatcher(_server_host.c_str(), _server_port, &h);
		delete user_name;
		delete public_key;
		ResponsePayload* server_response = d.GetResult();
		if (IsServerError(server_response)) {
			return;
		}
		SignupSuccessResponse* signup_response = dynamic_cast<SignupSuccessResponse*>(server_response);
		if (!signup_response) {
			std::cerr << "Server responded with unexpected response!" << std::endl << "--- Signup Failed! ---" << std::endl;
		}
		std::copy_n(signup_response->GetClientID().begin(), 16, std::begin(_user_id));
		this->_DumpUserInfo();
	}
	catch (NetworkException& e) {
		std::cerr << "Could not connect to server! Shutting down" << std::endl << "--- Signup Failed! ---" << std::endl;
		delete user_name;
		delete public_key;
		exit(-1);
	}
}

void Controller::UpdateUserList() {
	UserListRequest user_list = UserListRequest();
	RequestHeader h = RequestHeader(_user_id, USER_LIST_REQUEST, &user_list);
	try {
		Dispatcher d = Dispatcher(_server_host.c_str(), _server_port, &h);
		ResponsePayload* server_response = d.GetResult();
		if (IsServerError(server_response)) {
			return;
		}
		UserListResponse* user_list_response = dynamic_cast<UserListResponse*>(server_response);
		if (!user_list_response) {
			std::cerr << "Server responded with unexpected response!" << std::endl << "--- User List Update Request Failed! ---" << std::endl;
			return;
		}
		for (auto const& user : user_list_response->users)
		{
			User* u = new User(user->GetClientID(), user->GetClientName());
			std::cout << "\tUser Name: " << u->GetClientName()->data() << std::endl;
			(*_users)[*u->GetClientID()] = u;
		}
	}
	catch (NetworkException& e) {
		std::cerr << "Could not connect to server! Shutting down" << std::endl << "--- User List Update Request Failed! ---" << std::endl;
		exit(-1);
	}
}


std::array<char, 16> Controller::_GetUserIDByName(std::array<char, 255> user_name) {
	for (auto it = _users->begin(); it != _users->end(); it++)
	{
		if (*(it->second->GetClientName()) == user_name) {
			return it->first;
		}
	}
	throw UserNotFoundException();
}


void Controller::RequestPublicKey(std::array<char, 255> user_name) {
	std::array<char, 16> user_id;
	try {
		user_id = this->_GetUserIDByName(user_name);
	}
	catch (UserNotFoundException) {
		std::cerr << "User " << user_name.data() << " does not exist!" << std::endl;
		return;
	}
	UserPublicKeyRequest user_list = UserPublicKeyRequest(user_id);
	RequestHeader h = RequestHeader(_user_id, USER_PUBLIC_KEY_REQUEST, &user_list);
	try {
		Dispatcher d = Dispatcher(_server_host.c_str(), _server_port, &h);
		ResponsePayload* server_response = d.GetResult();
		if (IsServerError(server_response)) {
			return;
		}
		UserPublicKeyResponse* user_public_key_response = dynamic_cast<UserPublicKeyResponse*>(server_response);
		if (!user_public_key_response) {
			std::cerr << "Server responded with unexpected response!" << std::endl << "--- User Public Key Request Failed! ---" << std::endl;
		}
		(*_users)[user_id]->UpdatePublicKey(user_public_key_response->GetPublicKey());
	}
	catch (NetworkException& e) {
		std::cerr << "Server unexpectedly closed the connection!" << std::endl << "--- User Public Key Request Failed! ---" << std::endl;
		exit(-1);
	}
}


void Controller::GenerateSymmetricKeyForUser(std::array<char, 255> user_name) {
	std::array<char, 16> user_id;
	try {
		user_id = this->_GetUserIDByName(user_name);
	}
	catch (UserNotFoundException) {
		std::cerr << "User " << user_name.data() << " does not exist!" << std::endl;
		return;
	}
	this->_GenerateNewKeyForUser(user_id);
	auto s = _users->find(user_id);
	SendMessageRequest symmetic_key_message = SendMessageRequest(user_id, SYMMETRIC_KEY_RESPONSE, s->second->GetSymmetricKey()->size(), s->second->GetSymmetricKey()->data());
	RequestHeader h = RequestHeader(_user_id, USER_PUBLIC_KEY_REQUEST, &symmetic_key_message);
	try {
		Dispatcher d = Dispatcher(_server_host.c_str(), _server_port, &h);
		ResponsePayload* server_response = d.GetResult();
		if (IsServerError(server_response)) {
			return;
		}
		MessageSentResponse* user_public_key_response = dynamic_cast<MessageSentResponse*>(server_response);
		if (!user_public_key_response) {
			std::cerr << "Server responded with unexpected response!" << std::endl << "--- Could not send symmetric key to user! ---" << std::endl;
		}
	}
	catch (NetworkException& e) {
		std::cerr << "Server unexpectedly closed the connection!" << std::endl << "--- Could not send symmetric key to user! ---" << std::endl;
		exit(-1);
	}
}

void Controller::SendMessageToUser(std::array<char, 255> user_name, char* message_content, int message_size) {
	std::array<char, 16> user_id;
	try {
		user_id = this->_GetUserIDByName(user_name);
	}
	catch (UserNotFoundException) {
		std::cerr << "User " << user_name.data() << " does not exist!" << std::endl;
		return;
	}
	auto s = _users->find(user_id);
	SymmetricKeyEncryptor encrypotor = SymmetricKeyEncryptor(*s->second->GetSymmetricKey());
	std::string encrypted_message = encrypotor.ECBMode_Encrypt(message_content);
	SendMessageRequest encrypted_message_request = SendMessageRequest(user_id, REGULAR_MESSAGE_REQUEST, encrypted_message.length(), (char*)encrypted_message.c_str());
	RequestHeader h = RequestHeader(_user_id, USER_PUBLIC_KEY_REQUEST, &encrypted_message_request);
	try {
		Dispatcher d = Dispatcher(_server_host.c_str(), _server_port, &h);
		ResponsePayload* server_response = d.GetResult();
		if (IsServerError(server_response)) {
			return;
		}
		MessageSentResponse* user_public_key_response = dynamic_cast<MessageSentResponse*>(server_response);
		if (!user_public_key_response) {
			std::cerr << "Server responded with unexpected response!" << std::endl << "--- Could not send message to user! ---" << std::endl;
		}
	} catch (NetworkException& e) {
		std::cerr << "Server unexpectedly closed the connection!" << std::endl << "--- Could not send message to user! ---" << std::endl;
		exit(-1);
	}
}

void Controller::RequestSymmetricKeyFromUser(std::array<char, 255> user_name) {
	std::array<char, 16> user_id;
	try {
		user_id = this->_GetUserIDByName(user_name);
	}
	catch (UserNotFoundException) {
		std::cerr << "User " << user_name.data() << " does not exist!" << std::endl;
		return;
	}
	SendMessageRequest symmetic_key_request = SendMessageRequest(user_id, SYMMETRIC_KEY_REQUEST, 0, NULL);
	RequestHeader h = RequestHeader(_user_id, USER_PUBLIC_KEY_REQUEST, &symmetic_key_request);
	try {
		Dispatcher d = Dispatcher(_server_host.c_str(), _server_port, &h);
		ResponsePayload* server_response = d.GetResult();
		if (IsServerError(server_response)) {
			return;
		}
		MessageSentResponse* user_public_key_response = dynamic_cast<MessageSentResponse*>(server_response);
		if (!user_public_key_response) {
			std::cerr << "Server responded with unexpected response!" << std::endl << "--- Could not send symmetric key request to user! ---" << std::endl;
		}
	}
	catch (NetworkException& e) {
		std::cerr << "Server unexpectedly closed the connection!" << std::endl << "--- Could not send symmetric key request to user! ---" << std::endl;
		exit(-1);
	}
}

void Controller::RequestMessages() {
	MessageListRequest message_list_request = MessageListRequest();
	RequestHeader h = RequestHeader(_user_id, USER_PUBLIC_KEY_REQUEST, &message_list_request);
	try {
		Dispatcher d = Dispatcher(_server_host.c_str(), _server_port, &h);
		ResponsePayload* server_response = d.GetResult();
		SymmetricKeyEncryptor* encrypotor;
		std::string encrypted_message, decrypted_message;
		if (IsServerError(server_response)) {
			return;
		}
		AwaitingMessagesResponse* awaiting_messages = dynamic_cast<AwaitingMessagesResponse*>(server_response);
		if (!awaiting_messages) {
			std::cerr << "Server responded with unexpected response!" << std::endl << "--- Could not retrieve awaiting messages! ---" << std::endl;
			return;
		}
		for (auto message : awaiting_messages->messages) {
			auto sender = _users->find(message->GetSender());
			if (sender == _users->end()) { continue; }
			std::cout << "From: " << sender->second->GetClientName() << std::endl << "Content: " << std::endl;
			switch (message->GetMessageType()) {
			case SYMMETRIC_KEY_REQUEST:
				std::cout << "Request for symmetric key" << std::endl;
			case SYMMETRIC_KEY_RESPONSE:
				std::array<char, 128> user_symmetric_key;
				encrypted_message = std::string(message->GetMessageContent(), message->GetMessageSize());
				encrypotor = _key_manager->DecryptSymmetricKey(encrypted_message);
				std::copy_n(encrypotor->GetKey()->begin(), user_symmetric_key.size(), user_symmetric_key.begin());
				sender->second->UpdateSymmetricKey(user_symmetric_key);
				delete encrypotor;
				std::cout << "Symmetric key recieved" << std::endl;
			case REGULAR_MESSAGE_REQUEST:
				encrypotor = new SymmetricKeyEncryptor(*sender->second->GetSymmetricKey());
				encrypted_message = std::string(message->GetMessageContent(), message->GetMessageSize());
				decrypted_message = encrypotor->ECBMode_Decrypt(encrypted_message);
				delete encrypotor;
				std::cout << decrypted_message << std::endl;
			default:
				std::cerr << "Unexpected message type!" << std::endl;
			}
			std::cout << "----<EOM>--- " << std::endl << std::endl;
		}
	}
	catch (NetworkException& e) {
		std::cerr << "Server unexpectedly closed the connection!" << std::endl << "--- Could not retrieve awaiting messages! ---" << std::endl;
		exit(-1);
	}
}
