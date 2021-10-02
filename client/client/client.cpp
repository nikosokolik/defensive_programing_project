#include "Controller.h"

int main()
{
    Controller c = Controller();
    c.UpdateUserList();
    std::string user_name = "asd";
    std::array<char, 255> arr;
    arr.fill(0);
    std::copy_n(std::begin(user_name), user_name.size(), arr.begin());
    c.RequestPublicKey(arr);
}
