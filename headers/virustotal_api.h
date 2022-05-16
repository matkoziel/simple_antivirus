//
// Created by kozzi on 04.05.22.
//

#ifndef SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H
#define SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H

#include <cpprest/http_client.h>

void VirusTotalAnalyzeMultipleFiles(const std::string& path,const std::string& apiKey, bool quiet);

#endif //SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H

