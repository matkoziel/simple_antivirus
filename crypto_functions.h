//
// Created by kozzi on 3/9/22.
//

#include <iostream>

#ifndef ANTYWIRUSCLION_CRYPTO_FUNCTIONS_H
#define ANTYWIRUSCLION_CRYPTO_FUNCTIONS_H

std::string sha256(const std::string& str);

unsigned char* sha256File(const char *fileName);

#endif //ANTYWIRUSCLION_CRYPTO_FUNCTIONS_H
