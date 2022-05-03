//
// Created by kozzi on 4/25/22.
//

#include "../headers/monitor.h"

#include <sys/inotify.h>
#include <unistd.h>

#include "../libs/safe_queue.h"

#include <filesystem>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "../headers/file_functions.h"
#include "../headers/scan.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

SafeQueue<std::string> pathsToAnalyze;
std::vector<std::future<void>*> threads;

std::string generateFullPath(struct inotify_event* event, std::unordered_map<int,std::string>& wds) {
    auto dir = wds.find (event->wd);
    std::string fullPath = dir->second;
    fullPath.append("/");
    fullPath.append(event->name);
    return fullPath;
}

void checkForChanges(std::vector<std::string> &paths, int fileDescriptor, std::unordered_map<int,std::string>& wds) {
    char buffer[BUF_LEN];
    int length = read(fileDescriptor, buffer,BUF_LEN);
    int i{0};
    while(i<length) { // Reads block until event occurs
        auto *event = (struct inotify_event*) &buffer[i];
        if (event->len){
            if(event -> mask & IN_ISDIR){
                if (event-> mask & IN_CREATE){
                    std::string fullPath = generateFullPath(event,wds);
                    paths.push_back(fullPath);
                    wds.insert(std::pair<int, std::string>(inotify_add_watch(fileDescriptor,fullPath.c_str(),IN_MODIFY | IN_CREATE | IN_DELETE),fullPath));
                    std::cout << "Created new directory: " <<fullPath <<"\n";
                }
                else if (event-> mask & IN_MODIFY){
                    std::string fullPath = generateFullPath(event,wds);
                    std::cout << "Modified directory: " <<fullPath <<"\n";
                }
                else if (event-> mask & IN_DELETE){
                    std::string fullPath = generateFullPath(event,wds);
                    int found{0};
                    for (auto & wd : wds) {
                        if (wd.second == fullPath){
                            found= wd.first;
                            break;
                        }
                    }
                    if(found!=0){
                        wds.erase(found);
                        inotify_rm_watch(fileDescriptor,found);
                    }
                    std::cout << "Deleted directory: "<<fullPath <<"\n";
                }
            }
            else{
                if (event-> mask & IN_CREATE){
                    std::string fullPath = generateFullPath(event,wds);
                    std::cout <<"Created new file: " <<fullPath <<"\n";
//                    auto th = std::thread(AnalyzingFileWithoutFeedback,fullPath);
//                    th.join();
                    pathsToAnalyze.enqueue(fullPath);
//                    threads.push_back();
                }
                else if (event-> mask & IN_MODIFY){
                    std::string fullPath = generateFullPath(event,wds);
                    pathsToAnalyze.enqueue(fullPath);
                    std::cout <<"Modified file: " << fullPath <<"\n";
                }
                else if (event-> mask & IN_DELETE){
                    std::string fullPath = generateFullPath(event,wds);
                    std::cout <<"Deleted file: " << fullPath <<"\n";
                }
            }
        }
        i+= EVENT_SIZE + event->len;
    }
}

void monitorCatalogueTree(const std::string& path) {
    std::vector<std::string> paths{};
    paths.push_back(path);
    bool checkDirectory{};
    for (std::filesystem::path dir_entry :
            std::filesystem::recursive_directory_iterator(path,std::filesystem::directory_options::skip_permission_denied))
    {
        try{
            checkDirectory=CheckFileSystem(path)&&!std::filesystem::is_empty(path)&&std::filesystem::is_directory(dir_entry);
        } catch(const std::filesystem::filesystem_error& ex){
            checkDirectory=false;
        }
        if(checkDirectory){
            paths.push_back(dir_entry);
        }
    }
    int fileDescriptor = inotify_init();
    std::unordered_map<int,std::string> wds{};
    for (const std::string& wdPath : paths) {
        wds.insert(std::pair<int, std::string>(inotify_add_watch(fileDescriptor,wdPath.c_str(),IN_MODIFY | IN_CREATE | IN_DELETE),wdPath));
    }

    while(true) {
        checkForChanges(paths,fileDescriptor,wds);
    }
    for (const auto& wd : wds){
        inotify_rm_watch(fileDescriptor,wd.first);
    }
    close(fileDescriptor);

}