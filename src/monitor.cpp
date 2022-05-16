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
#include "../headers/main.h"
#include "../headers/scan.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

SafeQueue<std::string> pathsToAnalyze;
std::map<std::string,std::future<void>*> threads;

std::string generateFullPath(struct inotify_event* event, std::unordered_map<int,std::string>& wds) {
    auto dir = wds.find (event->wd);
    std::string fullPath = dir->second;
    fullPath.append("/");
    fullPath.append(event->name);
    return fullPath;
}

int ReadWithTimeout(int fileDescriptor, char *buffer,size_t length){
    fd_set read_fds, write_fds, except_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&except_fds);
    FD_SET(fileDescriptor, &read_fds);
    struct timeval timeout{};
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if (select(fileDescriptor + 1, &read_fds, &write_fds, &except_fds, &timeout) == 1)
    {
        return read(fileDescriptor, buffer,length);
    }
    else
    {
        return -1;
    }
}

void checkForChanges(std::vector<std::string> &paths, int fileDescriptor, std::unordered_map<int,std::string>& wds,char buffer[],int length) {
    int i{0};
    while(loop && (i<length)) { // Reads block until event occurs
        auto *event = (struct inotify_event*) &buffer[i];
        if (event->len){
            if(event -> mask & IN_ISDIR){
                if (event-> mask & IN_CREATE){
                    std::string fullPath = generateFullPath(event,wds);
                    paths.push_back(fullPath);
                    wds.insert(std::pair<int, std::string>(inotify_add_watch(fileDescriptor,fullPath.c_str(),IN_MODIFY | IN_CREATE | IN_DELETE),fullPath));
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
                }
            }
            else{
                if (event-> mask & IN_CREATE){
                    std::string fullPath = generateFullPath(event,wds);
                    std::cout << "File created\n";
                    pathsToAnalyze.enqueue(fullPath);
                }
                else if (event-> mask & IN_MODIFY){
                    std::string fullPath = generateFullPath(event,wds);
                    std::cout << "File created\n";
                    pathsToAnalyze.enqueue(fullPath);
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
    std::cout << "Loading all monitored files...\n";
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
    std::cout << "Successfully loaded all files\n";
    while(loop) {
        char buffer[BUF_LEN];
        int length = ReadWithTimeout(fileDescriptor, buffer,BUF_LEN);
        if(length!=-1){
            checkForChanges(paths,fileDescriptor,wds,buffer,length);
        }
    }
    for (const auto& wd : wds){
        inotify_rm_watch(fileDescriptor,wd.first);
    }
    close(fileDescriptor);
}