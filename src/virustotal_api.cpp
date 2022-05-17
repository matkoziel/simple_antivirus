//
// Created by kozzi on 04.05.22.
//

#include "../headers/virustotal_api.h"

#include <cpprest/http_client.h>
#include <cpprest/json.h>

#include "../headers/crypto_functions.h"
#include "../headers/main.h"
#include "../headers/file_functions.h"

//Creates API Request and return json object
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
//Generates output if file was considered as malicious
void GenerateOutput(const web::json::value& scans){
    auto scansMap = scans.as_object();
    std::cout << "File is considered to be malicious by:\n";
    for (const auto& scan : scansMap){
        if(scan.second.at(U("detected")).as_bool()){
            std::cout <<scan.first<<" -> "<<scan.second.at(U("result")).as_string()<<"\n";
        }
    }
}
//Analyze given file with VT API
void AnalyzeWithVTApi(const std::string& apiKey, const std::string& hash,const std::string& path){
    std::cout << "Sending request to VirusTotal API...\n";
    web::json::value data = VirusTotalReport(apiKey,hash);
    if(data.is_null()){
        std::cout << "Request with bad API Key, try again with proper API Key!\n";
        return;
    }
    if(data[U("response_code")].as_integer()==1){
        if(data[U("positives")].as_integer()!=0){
            auto scans = data[U("scans")];
            QuarantineAFile(path, quarantineDatabaseDB);
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
// Quiet option of analyzing file with API
void AnalyzeWithVTApiQuiet(const std::string& apiKey, const std::string& hash){
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
        }
    }
    else {
        if(data[U("verbose_msg")].as_string()=="Invalid resource, check what you are submitting"){
            std::cout << "Invalid hash, try again\n";
        }
    }
}
// Quiet option handling
void VirusTotalAnalyze(const std::string& path,const std::string& apiKey, bool quiet){
    std::string hash = MD5FileCryptoPP(path);
    std::cout << "Analyzing: " << path<< ", hash : " << hash << "\n";
    if(quiet){
        AnalyzeWithVTApiQuiet(apiKey,hash);
    }
    else{
        AnalyzeWithVTApi(apiKey,hash,path);
    }
}
// Recursively listing files and analyzing them
void VirusTotalAnalyzeMultipleFiles(const std::string& path,const std::string& apiKey, bool quiet){
    bool isDirectory;
    try{
        isDirectory = std::filesystem::is_directory(path);
    }
    catch (std::filesystem::filesystem_error const &ex) {
        std::cerr << "Permission denied\n";
        return;
    }
    if(isDirectory){
        std::vector<std::string> paths{};
        for (const std::filesystem::path &directoryIteratorPath : std::filesystem::recursive_directory_iterator(path,std::filesystem::directory_options::skip_permission_denied)) {
            paths.push_back(directoryIteratorPath.string());
        }
        if(paths.size()>100){           // Maximum files count accepted by API
            std::cerr << "API does not accept this amount of requests! Please try with smaller catalogues\n";
            return;
        }
        else{
            for(const auto& pathItr: paths){
                VirusTotalAnalyze(pathItr,apiKey,quiet);
            }
        }
    }
    else{
        VirusTotalAnalyze(path,apiKey,quiet);
    }
}



