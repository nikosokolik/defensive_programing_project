#include "User.h"


User::User(std::array<char, 16> client_id, std::array<char, 255> client_name) {
	_client_id = new std::array<char, 16>();
	_client_name = new std::array<char, 255>();
	_public_key = new std::array<char, 160>();
	_symmetric_key = new std::array<char, 16>();
	*_client_id = client_id;
	*_client_name = client_name;
}

void User::UpdatePublicKey(std::array<char, 160> public_key) {
	std::copy_n(public_key.begin(), public_key.size(), _public_key->begin());
	_is_public_key_set = true;
}

void User::UpdateSymmetricKey(std::array<char, 16> symmetric_key) {
	std::copy_n(symmetric_key.begin(), symmetric_key.size(), _symmetric_key->begin());
	_is_symmetric_key_set = true;
}

std::array<char, 16>* User::GetClientID() {
	return _client_id;
}

std::array<char, 255>* User::GetClientName() {
	return _client_name;
}

std::array<char, 160>* User::GetPublicKey() {
	return _public_key;
}

std::array<char, 16>* User::GetSymmetricKey() {
	return _symmetric_key;
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