//
// Created by kozzi on 3/9/22.
//

#include "../headers/main.h"

#include <termios.h>
#include <unistd.h>

#include <csignal>
#include <filesystem>
#include <future>
#include <iostream>

#include "../libs/CLI11.hpp"
#include "../libs/safe_queue.h"

#include "../headers/file_functions.h"
#include "../headers/monitor.h"
#include "../headers/scan.h"
#include "../headers/virustotal_api.h"


std::string quarantineDir;
std::string quarantineDatabase;
std::vector<std::string> quarantineDatabaseDB;
std::unordered_set<std::string> hashDatabaseDB;
std::atomic<bool> loop;

// Safe program termination
void TerminateProgram(int inputSignal){
    char input;
    signal(inputSignal,SIG_IGN);
    std::cout << "\nDo you really want to quit? [Y/N]\n";
    std::cin.read(&input,sizeof(char));
    if(input=='y'||input=='Y'||input=='T'||input=='t'){
        if(!quarantineDatabaseDB.empty()){
            SaveToQuarantineDatabase(quarantineDatabaseDB);
        }
        throw std::runtime_error("EXIT!");
    }
    else{
        signal(SIGINT, TerminateProgram);
    }
}
// Checks if given thread ended
bool FutureIsReady(std::future<void>* t){
    return t->wait_for(std::chrono::seconds(0)) == std::future_status::ready;
}
// Watcher that manages threads
void ThreadsWatcher(){
    loop=true;
    while(loop){
        if((threads.size()<=20)&&(loop||!threads.empty())){         //Limit amount of running threads to 20
            std::string path = pathsToAnalyze.dequeue();            //Gets path to analyze from safe queue
            if(threads.find(path)==threads.end()){               //Any of current threads is running with given path
                threads.insert(std::pair<std::string,            //Add thread to running threads
                               std::future<void>*>{path,
                                                   new std::future<void>{std::async(std::launch::async,
                                                                                    AnalyzingFileWithoutFeedback,path)}});
            }
            else {
                pathsToAnalyze.enqueue(path);                    //If any of given threads is running with given path enqueues path at the end of queue
            }
        }
        for (auto it = threads.begin();it!=threads.end();){ //Remove thread from running threads if finished
            if(FutureIsReady(it->second)){
                delete(it->second);                                     //Clear resources
                threads.erase(it++);
            }
            else{
                ++it;
            }
        }
    }
    while(!threads.empty()){                                            //Clear threads queue after finished monitoring
        for (auto it = threads.begin();it!=threads.end();){
            if(FutureIsReady(it->second)){
                delete(it->second);
                threads.erase(it++);
            }
            else{
                ++it;
            }
        }
    }
}
//Handles monitor termination
int TerminateHandler() {
    static bool initflag = false;
    static const int STDIN = 0;

    if (!initflag) {
        struct termios term{};
        tcgetattr(STDIN, &term);
        term.c_lflag &= ~ICANON;
        tcsetattr(STDIN, TCSANOW, &term);
        setbuf(stdin, NULL);
        initflag = true;
    }

    int nbbytes;
    ioctl(STDIN, FIONREAD, &nbbytes);
    return nbbytes;
}
bool checkQuarantineDatabase(){
    bool quarantineDatabaseExist{};
    try{
        quarantineDatabaseExist =std::filesystem::exists(quarantineDatabase);
    }catch(std::filesystem::filesystem_error const& ex) {
        std::cerr << "Permission denied: "<< quarantineDatabase <<" please check permissions\n";
        return EXIT_FAILURE;
    }
    if(quarantineDatabaseExist){
        return true;
    }
    else{
        try {
            std::ofstream file(quarantineDatabase, std::ios::out);      // Creates database file
            file.close();
            MakeQuarantineDatabaseUnavailable();
        } catch (std::filesystem::filesystem_error const &ex) {
            std::cerr << "Cannot create database in: " << quarantineDatabase << "\n";
            return EXIT_FAILURE;
        }
        try{
            quarantineDatabaseExist =std::filesystem::exists(quarantineDatabase);
        }catch(std::filesystem::filesystem_error const& ex) {
            std::cerr << "Permission denied: "<< quarantineDatabase <<" please check permissions\n";
            return EXIT_FAILURE;
        }
        if(quarantineDatabaseExist){
            return true;
        }
        else{
            return false;
        }
    }
}

bool checkQuarantineDir() {
    bool quarantineDirExist{};
    try{
        quarantineDirExist = std::filesystem::exists(quarantineDir);
    }catch(std::filesystem::filesystem_error const& ex) {
        std::cerr << "Permission denied: "<< quarantineDir <<" please check permissions\n";
        return EXIT_FAILURE;
    }
    if (quarantineDirExist) {
        return checkQuarantineDatabase();
    }
    else{
        try {
            std::filesystem::create_directory(quarantineDir);                       // Creates quarantine directory
            std::filesystem::permissions(quarantineDir, std::filesystem::perms::owner_all |
                                                        std::filesystem::perms::group_write |
                                                        std::filesystem::perms::group_read |
                                                        std::filesystem::perms::others_write |
                                                        std::filesystem::perms::others_read,
                                         std::filesystem::perm_options::replace);
        }catch(std::filesystem::filesystem_error const& ex){
            std::cerr << "Cannot create directory in: "<< quarantineDir<< "\n";
            return EXIT_FAILURE;
        }
        return checkQuarantineDatabase();
    }
}

int main(int argc, char **argv) {
    
    quarantineDir= getenv("HOME");
    quarantineDir=quarantineDir.append("/.quarantine");
    quarantineDatabase=quarantineDir +"/.quarantine_database.csv";
    quarantineDatabaseDB={};

    try{
        signal(SIGINT, TerminateProgram);
        CLI::App app{"Simple antivirus"};

        auto scanOpt=app.add_subcommand("scan", "Scan given path");
        auto restoreOpt=app.add_subcommand("restore", "Restore file from quarantine");
        auto showOpt = app.add_subcommand("show", "Show quarantined files");
        auto monitorOpt = app.add_subcommand("monitor", "Constant monitoring files in background");
        auto VTOpt = app.add_subcommand("vt", "Scan given files using VirusTotal API");

        std::string scanFileName{};
        scanOpt -> add_option("--path",scanFileName,"Path to file/directory we want to Scan")
                ->required()
                ->check(CLI::ExistingPath);

        std::string hashDatabaseStr="data/example_database.csv";
        auto d = scanOpt -> add_option("--d",hashDatabaseStr,"Path to hash database")
                ->check(CLI::ExistingPath);

        std::string restoreFileName{};
        restoreOpt -> add_option("--path",restoreFileName,"Path to file we want to restore");

        std::string monitorFileName{};
        monitorOpt -> add_option("--path",monitorFileName,"Path to file/directory we want to monitor")
                ->required()
                ->check(CLI::ExistingPath);
        auto dMonitor = monitorOpt -> add_option("--d",hashDatabaseStr,"Path to hash database")
                ->check(CLI::ExistingPath);

        std::string vtFilename{};
        VTOpt -> add_option("--path",vtFilename,"Path to file/directory we want to monitor")
                ->required()
                ->check(CLI::ExistingPath);
        std::string apiKey{};
        VTOpt -> add_option("--aK",apiKey,"Your VirusTotal API Key")
                ->required();
        bool quiet{false};
        VTOpt -> add_option("--q",quiet,"Less output option");

        CLI11_PARSE(app, argc, argv)
        if(!(*scanOpt || *restoreOpt || *showOpt||*VTOpt||*monitorOpt)){
            std::cout << "Subcommand is obligatory, type --help for more information\n";
        }
        if(*scanOpt){
            if(*d) {
                bool hashDatabaseAvailable{};
                try{
                    hashDatabaseAvailable=std::filesystem::exists(hashDatabaseStr);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::string message=std::filesystem::current_path().append("/").append(hashDatabaseStr);
                    std::cerr << "Cannot open default database in: " << message << "\n";
                    std::cerr << "Try to specify database running program with --d parameter\n";
                    return EXIT_FAILURE;
                }
                if(!hashDatabaseAvailable){
                    std::string message=std::filesystem::current_path().append("/").append(hashDatabaseStr);
                    std::cerr << "Cannot open default database in: " << message << "\n";
                    std::cerr << "Try to specify database by running program with --d parameter\n";
                    return EXIT_FAILURE;
                }
            }else{
                bool hashDatabaseAvailable{};
                try{
                    hashDatabaseAvailable=std::filesystem::exists(hashDatabaseStr);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::string message=std::filesystem::current_path().append("/").append(hashDatabaseStr);
                    std::cerr << "Cannot open default database in: " << message << "\n";
                    std::cerr << "Try to specify database running program with --d parameter\n";
                    return EXIT_FAILURE;
                }
                if(!hashDatabaseAvailable){
                    std::string message=std::filesystem::current_path().append("/").append(hashDatabaseStr);
                    std::cerr << "Cannot open default database in: " << message << "\n";
                    std::cerr << "Try to specify database by running program with --d parameter\n";
                    return EXIT_FAILURE;
                }
            }
            hashDatabaseDB = ReadDatabaseToUnorderedSet(hashDatabaseStr);
            if(checkQuarantineDir()){
                try {
                    quarantineDatabaseDB = ReadQuarantineDatabase(quarantineDatabase);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot load databases from: "<< quarantineDatabase <<" please check permissions\n";
                    return EXIT_FAILURE;
                }
                try {
                    std::filesystem::path scanPath (scanFileName);
                    std::string pathString = std::filesystem::canonical(
                            scanPath.parent_path().append(
                                    scanPath.filename().u8string()));
                    Scan(pathString);
                }
                catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot create canonical path of: "<< scanFileName<< "\n";
                    return EXIT_FAILURE;
                }
            }
            else{
                std::cerr << "Fatal error "<< "\n";
            }
        }
        if(*restoreOpt){
            try {
                quarantineDatabaseDB = ReadQuarantineDatabase(quarantineDatabase);
            }catch(std::filesystem::filesystem_error const& ex) {
                std::cerr << "Cannot load databases from: "<< quarantineDatabase <<" please check permissions\n";
                return EXIT_FAILURE;
            }
            try {
                std::filesystem::path restorePath (restoreFileName);
                std::string fileName = restorePath.filename();
                std::string fullDirectoryPath = std::filesystem::canonical(
                        restorePath.parent_path());
                std::string pathString = fullDirectoryPath + "/" + fileName;        // Creating full path name of given file
                if(!RestoreFromQuarantine(pathString, quarantineDatabaseDB)){
                    std::cerr << "No such file in quarantine database\n";
                    return EXIT_FAILURE;
                }
                else {
                    std::cout << "Successfully restored file: " << restoreFileName <<" from quarantine\n";
                }
            }
            catch(std::filesystem::filesystem_error const& ex) {
                std::cerr << "Cannot create canonical path of: "<< restoreFileName<< "\n";
                std::cout << ex.what() << "\n";
                return EXIT_FAILURE;
            }
        }
        if(*showOpt){
            bool quarantineDirExist{};
            bool quarantineDatabaseExist{};
            try{
                quarantineDirExist = std::filesystem::exists(quarantineDir);
                quarantineDatabaseExist =std::filesystem::exists(quarantineDatabase);
            }catch(std::filesystem::filesystem_error const& ex) {
                std::cerr << "Permission denied: "<< hashDatabaseStr<< " and: "<< quarantineDatabase <<" please check permissions\n";
                return EXIT_FAILURE;
            }
            if (quarantineDirExist && quarantineDatabaseExist) {
                try {
                    quarantineDatabaseDB = ReadQuarantineDatabase(quarantineDatabase);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot load database from: "<< quarantineDatabase <<" please check permissions\n";
                    return EXIT_FAILURE;
                }
                PrintQuarantineDatabase(quarantineDatabaseDB);
            }
            else {
                std::cerr << "Quarantine database: " << quarantineDatabase << " does not exist!";
                return EXIT_FAILURE;
            }
        }
        if(*monitorOpt){
            if(*dMonitor) {
                bool hashDatabaseAvailable{};
                try{
                    hashDatabaseAvailable=std::filesystem::exists(hashDatabaseStr);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::string message=std::filesystem::current_path().append("/").append(hashDatabaseStr);
                    std::cerr << "Cannot open default database in: " << message << "\n";
                    std::cerr << "Try to specify database running program with --d parameter\n";
                    return EXIT_FAILURE;
                }
                if(!hashDatabaseAvailable){
                    std::string message=std::filesystem::current_path().append("/").append(hashDatabaseStr);
                    std::cerr << "Cannot open default database in: " << message << "\n";
                    std::cerr << "Try to specify database by running program with --d parameter\n";
                    return EXIT_FAILURE;
                }
            }else{
                bool hashDatabaseAvailable{};
                try{
                    hashDatabaseAvailable=std::filesystem::exists(hashDatabaseStr);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::string message=std::filesystem::current_path().append("/").append(hashDatabaseStr);
                    std::cerr << "Cannot open default database in: " << message << "\n";
                    std::cerr << "Try to specify database running program with --d parameter\n";
                    return EXIT_FAILURE;
                }
                if(!hashDatabaseAvailable){
                    std::string message=std::filesystem::current_path().append("/").append(hashDatabaseStr);
                    std::cerr << "Cannot open default database in: " << message << "\n";
                    std::cerr << "Try to specify database by running program with --d parameter\n";
                    return EXIT_FAILURE;
                }
            }
            hashDatabaseDB = ReadDatabaseToUnorderedSet(hashDatabaseStr);
            if(checkQuarantineDir()){
                try {
                    quarantineDatabaseDB = ReadQuarantineDatabase(quarantineDatabase);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot load databases from: "<< quarantineDatabase <<" please check permissions\n";
                    return EXIT_FAILURE;
                }
                std::string pathString{};
                try {
                    std::filesystem::path path (monitorFileName);
                    std::string fileName = path.filename();
                    std::string fullDirectoryPath = std::filesystem::canonical(
                            path.parent_path());
                    pathString = fullDirectoryPath + "/" + fileName;        // Creating full path name of given file
                }
                catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot create canonical path of: "<< monitorFileName<< "\n";
                    return EXIT_FAILURE;
                }
                auto thWatcher = std::thread(ThreadsWatcher);                   // Initialize thread with watcher
                auto thMonitor = std::thread(MonitorCatalogueTree, pathString); // Initialize thread with monitor
                char c;
                bool check = true;
                while(check){                                                      // Watching for termination key
                    while (!TerminateHandler()) {
                        fflush(stdout);
                        sleep(1);
                    }
                    std::cin.read(&c,sizeof(char));
                    if (c==27||c==81||c==113){                                      // Terminates if q, Q or Esc
                        check=false;
                    }
                }
                std::cout << "\nSafely terminating program\n";
                loop=false;                                                        // Sets global atomic boolean to finish monitoring
                pathsToAnalyze.enqueue("");                                     // To avoid stuck in SafeQueue
                thWatcher.join();                                                  // Waits for thread to finish
                thMonitor.join();
            }
            else{
                std::cerr << "Fatal error "<< "\n";
            }
        }
        if(*VTOpt) {
            if(checkQuarantineDir()){
                try {
                    quarantineDatabaseDB = ReadQuarantineDatabase(quarantineDatabase);
                }catch(std::filesystem::filesystem_error const& ex) {
                    std::cerr << "Cannot load databases from: "<< quarantineDatabase <<" please check permissions\n";
                    return EXIT_FAILURE;
                }
                std::string pathString{};
                try {
                    std::filesystem::path path(vtFilename);
                    std::string fileName = path.filename();
                    std::string fullDirectoryPath = std::filesystem::canonical(
                            path.parent_path());
                    pathString = fullDirectoryPath + "/" + fileName;        // Creating full path name of given file
                }
                catch (std::filesystem::filesystem_error const &ex) {
                    std::cerr << "Cannot create canonical path of: " << vtFilename << "\n";

                    return EXIT_FAILURE;
                }
                if(quiet){
                    VirusTotalAnalyzeMultipleFiles(pathString,apiKey, true);
                }
                else{
                    VirusTotalAnalyzeMultipleFiles(pathString,apiKey, false);
                }
            }
        }
    }
    catch (std::runtime_error const &ex) {
        return EXIT_SUCCESS;
    }
}



