//
// Created by kozzi on 4/25/22.
//

#ifndef SIMPLE_ANTIVIRUS_MONITOR_H
#define SIMPLE_ANTIVIRUS_MONITOR_H

#include "../libs/safe_queue.h"

#include <future>
#include <string>
#include <map>
#include <thread>
#include <queue>


extern SafeQueue<std::string> pathsToAnalyze;
extern std::map<std::string,std::future<void>*> threads;

void MonitorCatalogueTree(const std::string& path);

#endif //SIMPLE_ANTIVIRUS_MONITOR_H
