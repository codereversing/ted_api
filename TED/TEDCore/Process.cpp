#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "psapi.lib")

#include "Process.h"

#include <algorithm>
#include <array>
#include <functional>

#include <Windows.h>
#include <DbgHelp.h>
#include <psapi.h>
#include <tlhelp32.h>

namespace TED
{
namespace Process
{

ThreadId CurrentThreadId()
{
	return static_cast<ThreadId>(GetCurrentThreadId());
}

std::vector<ThreadId> GetThreadIds()
{
	return GetThreadIds(GetCurrentProcessId());
}

std::vector<ThreadId> GetThreadIds(const ProcessId processId)
{
	std::vector<ThreadId> threadIds{};

	auto snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId) };
	if (snapshot == INVALID_HANDLE_VALUE) {
		return threadIds;
	}

	THREADENTRY32 threadEntry{};
	threadEntry.dwSize = sizeof(THREADENTRY32);
	if (Thread32First(snapshot, &threadEntry)) {
		do {
			if (threadEntry.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
				sizeof(threadEntry.th32OwnerProcessID)) {
				if (threadEntry.th32OwnerProcessID == processId) {
					threadIds.push_back(threadEntry.th32ThreadID);
				}
			}
			threadEntry.dwSize = sizeof(THREADENTRY32);
		} while (Thread32Next(snapshot, &threadEntry));
	}

	CloseHandle(snapshot);

	return threadIds;
}

static std::vector<ThreadId> InvokeOnThreadHandle(const std::vector<DWORD>& threadIds, std::function<DWORD(HANDLE)> operation)
{
	std::vector<ThreadId> failed{};

	for (const auto& threadId : threadIds) {
		auto handle{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (handle == INVALID_HANDLE_VALUE) {
			failed.push_back(threadId);
		}
		else {
			if (operation(handle) == static_cast<ThreadId>(-1)) {
				failed.push_back(threadId);
			}

			CloseHandle(handle);
		}

	}

	return failed;
}

std::vector<ThreadId> SuspendThreads(const std::vector<ThreadId>& threadIds)
{
	return InvokeOnThreadHandle(threadIds, SuspendThread);
}

std::vector<ThreadId> ResumeThreads(const std::vector<ThreadId>& threadIds)
{
	return InvokeOnThreadHandle(threadIds, ResumeThread);
}

HANDLE GetProcessHandle(const ProcessId processId)
{
	HANDLE processHandle{ GetCurrentProcess() };
	if (processId != GetCurrentProcessId()) {
		processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE, processId);
		if (processHandle == NULL) {
			return nullptr;
		}
	}

	return processHandle;
}

std::vector<HMODULE> GetModuleHandles(HANDLE processHandle)
{
	std::array<HMODULE, 256> handles{};
	DWORD modulesNeeded{};
	if (EnumProcessModules(processHandle, handles.data(), sizeof(HMODULE) * static_cast<DWORD>(handles.size()), &modulesNeeded)) {
		return std::vector<HMODULE>{handles.begin(), handles.begin() + (modulesNeeded / sizeof(HMODULE))};
	}

	return std::vector<HMODULE>{};
}

std::vector<Module> GetModules()
{
	return GetModules(GetCurrentProcessId());
}

std::vector<Module> GetModules(const ProcessId processId)
{
	std::vector<Module> modules{};

	auto processHandle{ GetProcessHandle(processId) };

	auto moduleHandles{ GetModuleHandles(processHandle) };
	for (const auto& moduleHandle : moduleHandles)
	{
		Module module{};

		std::array<char, MAX_PATH> moduleName{};
		auto result{ GetModuleFileNameExA(processHandle, moduleHandle, moduleName.data(), static_cast<DWORD>(moduleName.size())) };
		if (result) {
			module.name = moduleName.data();
		}

		MODULEINFO moduleInfo{};
		result = GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo,
			sizeof(MODULEINFO));
		if (result) {
			module.baseAddress = reinterpret_cast<Address>(moduleInfo.lpBaseOfDll);
			module.size = moduleInfo.SizeOfImage;
		}

		auto ntHeader{ ImageNtHeader(moduleHandle) };
		auto section{ IMAGE_FIRST_SECTION(ntHeader) };
		for (auto j{ 0 }; j < ntHeader->FileHeader.NumberOfSections; j++)
		{
			if (section->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) {
				module.executableSectionNames.push_back({ reinterpret_cast<char*>(section->Name),
					sizeof(section->Name) });
				module.executableSectionBaseAddresses.push_back(
					reinterpret_cast<Address>(moduleInfo.lpBaseOfDll) + section->VirtualAddress);
				module.executableSectionSizes.push_back(section->SizeOfRawData);
			}

			section++;
		}

		modules.push_back(module);
	}

	CloseHandle(processHandle);

	return modules;
}

bool LoadModule(std::string_view moduleName)
{
	return LoadLibraryA(moduleName.data());
}

bool UnloadModule(std::string moduleName)
{
	std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(),
		[](unsigned char c) { return std::tolower(c); });

	auto processHandle{ GetProcessHandle(GetCurrentProcessId()) };

	auto moduleHandles{ GetModuleHandles(processHandle) };
	for (const auto& moduleHandle : moduleHandles) {

		std::array<char, MAX_PATH> currentModuleName{};
		auto result{ GetModuleFileNameExA(processHandle, moduleHandle, currentModuleName.data(), static_cast<DWORD>(currentModuleName.size())) };
		if (result) {
			std::transform(currentModuleName.begin(), currentModuleName.end(), currentModuleName.begin(),
				[](unsigned char c) { return std::tolower(c); });
			if (moduleName == currentModuleName.data()) {
				return FreeLibrary(moduleHandle);
			}
		}
	}

	return false;
}

void Terminate()
{
	TerminateProcess(GetCurrentProcess(), 0);
}

}
}