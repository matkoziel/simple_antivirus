//
// Created by kozzi on 04.05.22.
//

#ifndef SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H
#define SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H

#include <cpprest/http_client.h>

void VirusTotalReport(const std::string& apiKey, const std::string& hash);

#endif //SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H
