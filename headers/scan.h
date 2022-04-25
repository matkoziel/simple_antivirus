//
// Created by kozzi on 14.04.2022.
//

#ifndef SIMPLE_ANTIVIRUS_SCAN_H
#define SIMPLE_ANTIVIRUS_SCAN_H

#include <string>
#include <unordered_set>
#include <vector>

void Scan(const std::string& path, std::unordered_set<std::string>& hashes, std::vector<std::string>& quarantineDB);


#endif //SIMPLE_ANTIVIRUS_SCAN_H
