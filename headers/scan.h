//
// Created by kozzi on 14.04.2022.
//

#ifndef SIMPLE_ANTIVIRUS_SCAN_H
#define SIMPLE_ANTIVIRUS_SCAN_H

#include <string>
#include <unordered_set>
#include <vector>

void Scan(const std::string& path);

void AnalyzingFileWithoutFeedback(const std::string& pathString);

#endif //SIMPLE_ANTIVIRUS_SCAN_H
