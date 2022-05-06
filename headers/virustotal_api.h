//
// Created by kozzi on 04.05.22.
//

#ifndef SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H
#define SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H

#include <cpprest/http_client.h>

void getRequest();

web::json::value createJson(const std::string& fileContent);

#endif //SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H
