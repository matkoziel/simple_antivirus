//
// Created by kozzi on 04.05.22.
//

#include "../headers/virustotal_api.h"

#include <cpprest/http_client.h>
#include <cpprest/uri.h>
#include <cpprest/json.h>
#include <cryptopp/files.h>

#include "../headers/crypto_functions.h"

web::json::value VirusTotalReport(const std::string& apiKey, const std::string& hash){
    std::string requestUri = "https://www.virustotal.com/vtapi/v2/file/report?apikey=";
    requestUri.append(apiKey);
    requestUri.append("&resource=");
    requestUri.append(hash);
    requestUri.append("&allinfo=true");

    web::http::client::http_client client(U(requestUri));

    web::http::http_request req(web::http::methods::GET);
    auto response = client.request(req).get();
    return response.extract_json().get();
}
void GenerateOutput(const web::json::value& scans){
    auto scansMap = scans.as_object();
    std::cout << "File is considered to be malicious by:\n";
    for (const auto& scan : scansMap){
        if(scan.second.at(U("detected")).as_bool()){
            std::cout <<scan.first<<" -> "<<scan.second.at(U("result")).as_string()<<"\n";
        }
    }
}
void AnalyzeWithVTApi(const std::string& apiKey, const std::string& hash){
    std::cout << "Sending request to VirusTotal API...\n";
    web::json::value data = VirusTotalReport(apiKey,hash);
    if(data.is_null()){
        std::cout << "Request with bad API Key, try again with proper API Key!\n";
        return;
    }
    if(data[U("response_code")].as_integer()==1){
        if(data[U("positives")].as_integer()!=0){
            auto scans = data[U("scans")];
            GenerateOutput(scans);
        }
        else{
            std::cout << "File is considered to be safe\n";
        }
    }
    else {
        if(data[U("verbose_msg")].as_string()=="The requested resource is not among the finished, queued or pending scans"){
            std::cout << "File is probably safe, not present in database\n";
        }
        if(data[U("verbose_msg")].as_string()=="Invalid resource, check what you are submitting"){
            std::cout << "Invalid hash, try again\n";
        }
    }
}
void VirusTotalAnalyze(const std::string& path,const std::string& apiKey, bool quiet){
    std::string hash{};
    try {
        hash = MD5FileCryptoPP(path);
        std::cout << "Analyzing: " << path<< ", hash : " << hash << "\n";
    }
    catch (CryptoPP::FileStore::OpenErr const & ex){
        std::cerr << "Failed hashing file, "<<ex.GetWhat()<<"\n";
        return;
    }
    catch (CryptoPP::FileStore::ReadErr const & ex){
        std::cerr << "Failed hashing file, "<<ex.GetWhat()<<"\n";
        return;
    }
    if(quiet){
        //TODO: Add quiet method
    }
    else{
        AnalyzeWithVTApi(apiKey,hash);
    }
}



