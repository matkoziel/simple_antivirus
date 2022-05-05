//
// Created by kozzi on 04.05.22.
//

#include "../headers/virustotal_api.h"

#include <cpprest/http_client.h>

//void getRequest(){
//    web::http::client::http_client client("http://httpbin.org/");
//
//    web::http::http_response response;
//    // ordinary `get` request
//    response = client.request(web::http::methods::GET, "/get").get();
//    std::cout << response.extract_string().get() << "\n";
//
//    // working with json
//    response = client.request(web::http::methods::GET, "/get").get();
//    std::cout << "url: " << response.extract_json().get()[U("url")] << "\n";
//}
