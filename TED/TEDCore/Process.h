#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "CommonTypes.h"

namespace TED
{
namespace Process
{

using ProcessId = unsigned long;
using ThreadId = unsigned long;

typedef struct {
	std::string name;
	Address baseAddress;
	unsigned long size;
	std::vector<std::string> executableSectionNames;
	std::vector<Address> executableSectionBaseAddresses;
	std::vector<unsigned long> executableSectionSizes;
} Module;

ThreadId CurrentThreadId();
std::vector<ThreadId> GetThreadIds();
std::vector<ThreadId> GetThreadIds(const ProcessId processId);
std::vector<ThreadId> SuspendThreads(const std::vector<ThreadId>& threadIds);
std::vector<ThreadId> ResumeThreads(const std::vector<ThreadId>& threadIds);

std::vector<Module> GetModules();
std::vector<Module> GetModules(const ProcessId processId);

bool LoadModule(std::string_view moduleName);
bool UnloadModule(std::string moduleName);

void Terminate();

}
}