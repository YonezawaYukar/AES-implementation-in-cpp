//
// Created by YonezawaYukari on 2022/10/30.
//

#ifndef AES_CRYPT_BASE64_H
#define AES_CRYPT_BASE64_H

#include<zconf.h>
#include <vector>
#include <string>
typedef unsigned char BYTE;

std::string base64_encode(BYTE const* buf, unsigned int bufLen);
std::vector<Byte> base64_decode(std::string const&);


#endif //AES_CRYPT_BASE64_H
