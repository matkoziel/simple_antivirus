//
// Created by kozzi on 04.05.22.
//

#include "../headers/virustotal_api.h"

#include <cpprest/http_client.h>
#include <cpprest/json.h>

web::json::value createJson(const std::string& fileContent){
    web::json::value headers;
    std::string apiKey = "4eb5b9181ba96807ad99fa242f6130bdf594d9d68ecb965f0a0e61f7f1efdb07";
    headers["x-apikey"] = web::json::value::string(apiKey);
    web::json::value files;
    files["file\\"]=web::json::value::string(fileContent);
    web::http::client::http_client client(U("https://www.virustotal.com/api/v3/files"));
    web::http::http_request request(web::http::methods::POST);
    request.headers().add("x-apikey","4eb5b9181ba96807ad99fa242f6130bdf594d9d68ecb965f0a0e61f7f1efdb07");
    request.set_body(files);
    web::http::http_response response = client.request(request).get();
    std::cout << response.extract_string().get() << "\n";
//    headers[""]
    std::cout << headers.serialize() <<"\n";
}


void getRequest(){
    web::http::client::http_client client("http://httpbin.org/");

    web::http::http_response response;
    // ordinary `get` request
    response = client.request(web::http::methods::GET, "/get").get();
    std::cout << response.extract_string().get() << "\n";

    // working with json
    response = client.request(web::http::methods::GET, "/get").get();
    std::cout << "url: " << response.extract_json().get()[U("url")] << "\n";
}
