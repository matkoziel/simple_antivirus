//
// Created by kozzi on 04.05.22.
//

#include "../headers/virustotal_api.h"

#include <cpprest/http_client.h>
#include <cpprest/uri.h>
#include <cpprest/json.h>

void VirusTotalReport(const std::string& apiKey, const std::string& hash){
    std::string requestUri = "https://www.virustotal.com/vtapi/v2/file/report?apikey=";
    requestUri.append(apiKey);
    requestUri.append("&resource=");
    requestUri.append(hash);
    requestUri.append("&allinfo=true");

    web::http::client::http_client client(U(requestUri));
    web::http::http_request req(web::http::methods::GET);
    auto response = client.request(req).get();
    std::cout << response.extract_json().get() << "\n";
}



