#include "User.h"


User::User(std::array<char, 16> client_id, std::array<char, 255> client_name) {
	_client_id = new std::array<char, 16>();
	_client_name = new std::array<char, 255>();
	_public_key = new std::array<char, 160>();
	_symmetric_key = new std::array<char, 128>();
	*_client_id = client_id;
	*_client_name = client_name;
}

void User::UpdatePublicKey(std::array<char, 160> public_key) {
	*_public_key = public_key;
	_is_public_key_set = true;
}

void User::UpdateSymmetricKey(std::array<char, 128> symmetric_key) {
	*_symmetric_key = symmetric_key;
	_is_symmetric_key_set = true;
}

std::array<char, 16>* User::GetClientID() {
	std::array<char, 16>* retval = new std::array<char, 16>();
	retval = _client_id;
	return retval;
}

std::array<char, 255>* User::GetClientName() {
	std::array<char, 255>* retval = new std::array<char, 255>();
	retval = _client_name;
	return retval;
}

std::array<char, 160>* User::GetPublicKey() {
	std::array<char, 160>* retval = new std::array<char, 160>();
	retval = _public_key;
	return retval;
}

std::array<char, 128>* User::GetSymmetricKey() {
	std::array<char, 128>* retval = new std::array<char, 128>();
	retval = _symmetric_key;
	return retval;
}

User::~User() {
	if (_client_id) {
		delete _client_id;
	}
	if (_client_name) {
		delete _client_name;
	}
	if (_public_key) {
		delete _public_key;
	}
	if (_symmetric_key) {
		delete _symmetric_key;
	}
}