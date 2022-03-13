//
// Created by kozzi on 3/9/22.
//

#include "file_management.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <algorithm>

std::string readFileToString(const std::string& path)
{
    std::string output;
    std::ifstream inputFile(path);
    if (!inputFile)
    {
        std::cerr << "Wystapił błąd, podany plik nie istnieje\n";
    }
    else
    {
        output.assign((std::istreambuf_iterator<char>(inputFile)),std::istreambuf_iterator<char>());
    }
    inputFile.close();
    return output;
}

std::vector<std::string> readDatabase(const std::string& path)
{
    std::vector<std::string> output;
    std::ifstream inputFile(path,std::ios::out);
    if (!inputFile)
    {
        std::cerr << "Wystapił błąd, podany plik nie istnieje\n";
    }
    else
    {
        std::string temp;
        while(getline(inputFile, temp)){
            output.push_back(temp);
        }
    }
    inputFile.close();
    return output;
}

std::vector<unsigned char> readFileBinary(const std::string& path)
{
    std::vector<unsigned char> output;
    std::ifstream inputFile(path, std::ios::binary);
    if (!inputFile)
    {
        std::cerr << "Wystapił błąd, podany plik nie istnieje\n";
    }
    else
    {
        output.assign((std::istreambuf_iterator<char>(inputFile)),std::istreambuf_iterator<char>());
    }
    inputFile.close();
    return output;
}

void appendToFile(const std::string& input, const std::string& path)
{
    const char separator = '\n';
    std::ofstream outputFile;
    outputFile.open(path, std::ios_base::app);
    if (!outputFile)
    {
        std::cerr << "Wystapił błąd, podany plik nie istnieje\n";
    }
    else
    {
        outputFile << input + separator;
    }
    outputFile.close();
}

std::vector<std::string> getAllFilesInDirectory(const std::string& path)
{
    std::vector<std::string> result;

    for (const std::filesystem::path& dir : std::filesystem::recursive_directory_iterator(path))
    {
        std::string path_string{dir.u8string()};
        result.push_back(path_string);
    }
    return result;
}
