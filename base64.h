//
// Created by YonezawaYukari on 2022/10/30.
//

#ifndef AES_CRYPT_BASE64_H
#define AES_CRYPT_BASE64_H

#include <zconf.h>
#include <vector>
#include <string>


std::string base64_encode(Byte const *buf, unsigned int bufLen);

std::vector<Byte> base64_decode(std::string const &);


#endif //AES_CRYPT_BASE64_H
