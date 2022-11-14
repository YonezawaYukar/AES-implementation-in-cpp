
#include <iostream>
#include "aes.h"

using namespace std;

int main() {
    auto aes_class = new aes();
    string key = "Where is the key?😊";
    string msg = "It's a msg...🐱";
    string enc = aes_class->encrypt(msg, key, 256);
    string dec = aes_class->decrypt(enc, key, 256);
    cout<< "Msg: "<< msg << endl;
    cout << "Key: " << key << endl;
    cout << "Encrypted: " << enc << endl;
    cout << "Decrypted: " << dec << endl;
    return 0;
}
