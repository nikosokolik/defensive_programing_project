#pragma once
#include <array>


class User {
private:
	std::array<char, 16>* _client_id = NULL;
	std::array<char, 255>* _client_name = NULL;
	std::array<char, 160>* _public_key = NULL;
	std::array<char, 128>* _symmetric_key = NULL;
	bool _is_public_key_set = false;
	bool _is_symmetric_key_set = false;
public:
	User(std::array<char, 16> client_id, std::array<char, 255> client_name);
	virtual ~User();
	void UpdatePublicKey(std::array<char, 160> public_key);
	void UpdateSymmetricKey(std::array<char, 128> symmetric_key);
	std::array<char, 16> *GetClientID();
	std::array<char, 255> *GetClientName();
	std::array<char, 160> *GetPublicKey();
	std::array<char, 128> *GetSymmetricKey();
};