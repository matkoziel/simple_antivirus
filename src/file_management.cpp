//
// Created by kozzi on 3/9/22.
//

#include "../headers/file_management.h"
#include "../headers/crypto_functions.h"
#include "../headers/main.h"

#include <iostream>
#include <filesystem>
#include <unordered_set>

#include<sys/vfs.h>

bool findInUnorderedSet(const std::string& value, const std::unordered_set<std::string>& unorderedSet) {
    return unorderedSet.find(value) != unorderedSet.end();
}

std::string renameFileToAvoidConflicts() {
    std::string temp;
    temp.append(quarantineDir);
    temp.append("/malicious_file");
    temp.append("_0");
    while(std::filesystem::exists(temp)) {
        int index = temp.find_last_of('_');
        int newNumber = std::stoi(temp.substr(index+1,temp.size()));
        temp = temp.substr(0,index+1).append(std::to_string(newNumber+1));
    }
    return temp;
}

bool moveFile(const std::string& from, const std::string& to) {
    if(!std::filesystem::exists(from)) {
        std::cerr << "No such file! : " << from << "\n";
        return false;
    }
    else {
        std::filesystem::rename(from,to);
        if(!std::filesystem::exists(from)) {
            return true;
        }
        else {
            std::cerr << "Error occurred, could not move file : " << from <<" to: " << to << "\n";
            return false;
        }
    }
}
void checkForDuplicate(const std::string& input, std::unordered_set<std::string>& database){
    int delimiter = input.find_first_of(',');
    std::string temp1 = input.substr(0,delimiter);
    std::string toRemove{};
    for (std::string line : database){
        int delimiter = line.find_first_of(',');
        std::string temp = line.substr(0,delimiter);
        if (temp == temp1){
            toRemove=line;
            database.insert(input);
            break;
        }
    }
    database.insert(input);
    if(!toRemove.empty()){
        auto iterator = database.find(toRemove);
        std::cout << iterator->c_str() << "\n";
        database.erase(iterator);
    }
}

void saveToDatabase(const std::unordered_set<std::string>& database) {
    std::ofstream outputFile;
    outputFile.open(quarantineDatabase, std::ios_base::out);
    for (std::string line : database){
        outputFile << line +"\n";
    }
    outputFile.close();
}

void appendToDatabase(const std::string& input, std::unordered_set<std::string>& database) {
//    database.insert(input);
    checkForDuplicate(input,database);
    saveToDatabase(database);
}

std::unordered_set<std::string> readDatabaseToUnorderedSet(const std::string& path) {
    std::unordered_set<std::string> output;
    std::ifstream inputFile(path,std::ios::out);
    if (!inputFile) {
        std::cerr << "Error, cannot load database from: " << path << "\n";
    }
    else {
        std::string temp;
        while(getline(inputFile, temp)) {
            output.insert(temp);
        }
    }
    inputFile.close();
    return output;
}
std::unordered_set<std::string> readDatabaseToVector(const std::string& path) {
    std::unordered_set<std::string> output;
    std::ifstream inputFile(path,std::ios::out);
    if (!inputFile) {
        std::cerr << "Error, cannot load database from: " << path << "\n";
    }
    else {
        std::string temp;
        while(getline(inputFile, temp)) {
            output.insert(temp);
        }
    }
    inputFile.close();
    return output;
}
void removeExecutePermissions(const std::string& path) {
    if(exists(std::filesystem::path(path))){
        std::filesystem::permissions(path,std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                          std::filesystem::perms::group_read | std::filesystem::perms::group_write |
                                          std::filesystem::perms::others_read,std::filesystem::perm_options::replace);
        std::cout << "File " << path << " moved to: " << path << "\n";
    }
    else {
        std::cerr << "Error occurred, no such file: " << path << "\n";
    }
}

AESCryptoData quarantineAFile(const std::string& path, std::unordered_set<std::string>& database) {
    AESCryptoData aes{};
    std::string movedTo = renameFileToAvoidConflicts();
    aes.prevName=path;
    aes.inQuarantineName = movedTo;
    aes.perms = status(std::filesystem::path(path)).permissions();
    encryptFile(aes,database);
    removeExecutePermissions(aes.inQuarantineName);
    return aes;
}

bool checkFile(const std::string& hash, const std::unordered_set<std::string>& hashes) {
    return findInUnorderedSet(hash, hashes);
}

void analyzingFile(const std::string& pathString, std::unordered_set<std::string>& hashes, std::unordered_set<std::string>& quarantineDB) {
    std::cout << "Analyzing: " << pathString;
    std::string hash = md5FileCryptoPP(pathString);
    std::cout << ", hash : " << hash << "\n";
//        std:: cout << ", hash : " << hash << "\t\r" << std::flush;
    if (checkFile(hash, hashes)) {
        std::cout << "Found potentially malicious file: " << pathString << "\n";
        quarantineAFile(pathString, quarantineDB);
        try {
            std::filesystem::remove(pathString);
        }
        catch (std::filesystem::filesystem_error const &ex) {
            std::cerr << ex.code().message() << ": " << pathString << "\n";
        }
    }
}

int checkFileSystem(const std::string& path) {
    struct statfs sb{};
    if ((statfs(path.c_str(), &sb)) == 0) {
        if (sb.f_type == 40864) return -1;
        else return 1;
    } else return -1;
}

AESCryptoData findInQuarantine(const std::string& prevPath, const std::unordered_set<std::string>& quarantineDb){
    AESCryptoData aes{};
    std::array<std::string,5> quarantineData{};
    for (std::string line : quarantineDb){
        int start = 0;
        int delimiter = line.find_first_of(',');
        std::string temp = line.substr(start,delimiter);
        if (temp == prevPath){
            quarantineData[0]=temp;
            for (int i = 1; i<5; i++){
                line = line.erase(start,delimiter+1);
                delimiter = line.find_first_of(',');
                quarantineData[i]=line.substr(start,delimiter);
            }
            break;
        }
    }
    if(quarantineData[0].empty()) return aes;
    aes.prevName=quarantineData[0];
    aes.inQuarantineName=quarantineData[1];
    aes.keyString=quarantineData[2];
    aes.ivString=quarantineData[3];
    aes.perms= static_cast<std::filesystem::perms>(std::stoi(quarantineData[4]));
    return aes;
}

void addToQuarantineDatabase(const AESCryptoData& aes, std::unordered_set<std::string>& database) {
    std::stringstream ss;
    ss<< aes.prevName << "," << aes.inQuarantineName << "," << aes.keyString << "," <<aes.ivString << ","<< static_cast<int>(aes.perms);
    appendToDatabase(ss.str(),database);
}

bool restoreFromQuarantine(const std::string& path, const std::unordered_set<std::string>& quarantineDb){
    AESCryptoData aes = findInQuarantine(path,quarantineDb);
    if(aes.prevName.empty()){
        return false;
    }
    decryptFile(aes);
    std::filesystem::permissions(aes.prevName,aes.perms,std::filesystem::perm_options::replace);
    return true;
}

void scanAllFilesInDirectory(const std::string& path, std::unordered_set<std::string>& hashes,std::unordered_set<std::string>& quarantineDB) {
    int nonRegularFiles=0;
    int symlinks=0;
    long long regularFiles=0;
        for (const std::filesystem::path &directoryIteratorPath : std::filesystem::recursive_directory_iterator(path,std::filesystem::directory_options::skip_permission_denied)) {
            if ((checkFileSystem(directoryIteratorPath) == 1) && exists(directoryIteratorPath)) {
                if (std::filesystem::status(directoryIteratorPath).type() == std::filesystem::file_type::regular) {
                    if (std::filesystem::is_symlink(directoryIteratorPath)) {
                        std::string pathString = std::filesystem::canonical(
                                directoryIteratorPath.parent_path().append(
                                        directoryIteratorPath.filename().u8string()));
                        if (std::filesystem::status(pathString).type() == std::filesystem::file_type::regular) {
                            if (!std::filesystem::is_empty(pathString)) {
                                analyzingFile(pathString, hashes,quarantineDB);
                                symlinks++;
                            }
                        } else {
                            nonRegularFiles++;
                        }

                    } else {
                        std::string pathString{directoryIteratorPath.u8string()};
                        if (!std::filesystem::is_empty(pathString)) {
                            analyzingFile(pathString, hashes,quarantineDB);
                            regularFiles++;
                        }
                    }
                } else {
                    nonRegularFiles++;
                }
            } else nonRegularFiles++;
        }
        std::cout << "Scanned: \n";
        std::cout << "Regular files: " << regularFiles << "\n";
        std::cout << "Non regular files: " << nonRegularFiles << "\n";
        std::cout << "Symlinks: " << symlinks << "\n";
}

void scan(const std::string& path, std::unordered_set<std::string>& hashes,std::unordered_set<std::string>& quarantineDB){
    std::cout << "Work in progress...\n";
    try {
        bool isDirectory = std::filesystem::is_directory(path);
        if(isDirectory){
            scanAllFilesInDirectory(path,hashes,quarantineDB);
        }
        else {
            const std::filesystem::path &directoryIteratorPath(path);
            if ((checkFileSystem(directoryIteratorPath) == 1) && exists(directoryIteratorPath)) {
                if (std::filesystem::status(directoryIteratorPath).type() == std::filesystem::file_type::regular) {
                    if (std::filesystem::is_symlink(directoryIteratorPath)) {
                        std::string pathString = std::filesystem::canonical(
                                directoryIteratorPath.parent_path().append(
                                        directoryIteratorPath.filename().u8string()));
                        if (std::filesystem::status(pathString).type() == std::filesystem::file_type::regular) {
                            if (!std::filesystem::is_empty(pathString)) {
                                analyzingFile(pathString, hashes,quarantineDB);
                            }
                        } else {
                            std::cout << "Failed\n";
                        }

                    } else {
                        std::string pathString{directoryIteratorPath.u8string()};
                        if (!std::filesystem::is_empty(pathString)) {
                            analyzingFile(pathString, hashes,quarantineDB);
                        }
                    }
                } else {
                    std::cout << "Failed\n";
                }
            } else std::cout << "Failed\n";
        }
    }
    catch(std::filesystem::filesystem_error const& ex) {
        std::cerr << ex.code().message() <<": "<< path<< "\n";
    }
}


