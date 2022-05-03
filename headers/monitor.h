//
// Created by kozzi on 4/25/22.
//

#ifndef SIMPLE_ANTIVIRUS_MONITOR_H
#define SIMPLE_ANTIVIRUS_MONITOR_H

#include "../libs/safe_queue.h"

#include <future>
#include <string>
#include <thread>
#include <queue>



extern SafeQueue<std::string> pathsToAnalyze;
extern std::vector<std::future<void>*> threads;

void monitorCatalogueTree(const std::string& path);

#endif //SIMPLE_ANTIVIRUS_MONITOR_H
