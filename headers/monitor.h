//
// Created by kozzi on 4/25/22.
//

#ifndef SIMPLE_ANTIVIRUS_MONITOR_H
#define SIMPLE_ANTIVIRUS_MONITOR_H

#include <string>
#include <thread>
#include <vector>


extern std::vector<std::thread> threads;

void monitorCatalogueTree(const std::string& path);

#endif //SIMPLE_ANTIVIRUS_MONITOR_H
