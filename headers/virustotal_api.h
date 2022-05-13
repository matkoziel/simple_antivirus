//
// Created by kozzi on 04.05.22.
//

#ifndef SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H
#define SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H

#include <cpprest/http_client.h>

web::json::value VirusTotalReport(const std::string& apiKey, const std::string& hash);

void AnalyzeWithVTApi(const std::string& apiKey, const std::string& hash);

void VirusTotalAnalyze(const std::string& path,const std::string& apiKey, bool quiet);

#endif //SIMPLE_ANTIVIRUS_VIRUSTOTAL_API_H

