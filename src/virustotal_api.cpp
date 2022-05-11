//
// Created by kozzi on 04.05.22.
//

#include "../headers/virustotal_api.h"

#include <curl/curl.h>



void cCurl(){
    CURL *hnd = curl_easy_init();

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/vtapi/v2/file/scan");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: text/plain");
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, "file=data%base64%&apikey=4eb5b9181ba96807ad99fa242f6130bdf594d9d68ecb965f0a0e61f7f1efdb07");

    CURLcode ret = curl_easy_perform(hnd);
    std::cout << ret << "\n";
}

