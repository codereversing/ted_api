#pragma comment(lib, "DbgHelp.lib")

#include "Breakpoint.h"

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "Memory.h"
#include "Process.h"

namespace TED
{
namespace Breakpoint
{

#ifdef _M_IX86

static std::unordered_map<DWORD, DWORD> threadsTls{};
static std::mutex mapMutex{};

Address* brokenAddress()
{
	// thread_local storage seems to have some issues properly
	// initializing on x86 builds. Manually creating a TLS index
	// as a workaround. The allocated index isn't getting freed
	// but not really expecting it to be an issue since most
	// applications don't create and kill gigantic amounts of threads.
	auto currentThreadId{ GetCurrentThreadId() };

	if (!threadsTls.contains(currentThreadId)) {
		auto newTlsIndex{ TlsAlloc() };
		if (newTlsIndex != TLS_OUT_OF_INDEXES) {
			TlsSetValue(newTlsIndex, new Address{});

			std::scoped_lock{ mapMutex };
			threadsTls.insert({ currentThreadId, newTlsIndex });
		}
		else {
			assert("Out of TLS indexes");
		}
	}

	std::scoped_lock{ mapMutex };
	return reinterpret_cast<Address*>(TlsGetValue(threadsTls[currentThreadId]));
}
#define brokenAddress *brokenAddress()

#elif defined _M_AMD64
thread_local Address brokenAddress{};
#endif

static std::unordered_map<Address, std::vector<Address>> breakpointRanges{};

static std::unordered_map<Address, unsigned char> int3ToOriginalByte{};
static std::unordered_set<Address> int3Breakpoints{};

static std::unordered_set<Address> callStackBreakpoints{};
static std::unordered_set<Address> immediateBreakpoints{};

static bool autoDisableMode{};

moodycamel::ConcurrentQueue<BreakpointEvent> breakpointEvents{};

bool AddImmediateBreakpoint(Address address)
{
	return immediateBreakpoints.insert(address).second;
}

bool RemoveImmediateBreakpoint(Address address)
{
	return immediateBreakpoints.erase(address) != 0;
}

bool IsImmediateBreakpoint(Address address)
{
	return immediateBreakpoints.contains(address);
}

bool EnableCallStack(Address address)
{
	return callStackBreakpoints.insert(address).second;
}

bool DisableCallStack(Address address)
{
	return callStackBreakpoints.erase(address) != 0;
}

bool IsCallStackBreakpoint(Address address)
{
	return callStackBreakpoints.contains(address);
}

bool AddInt3BreakpointInternal(Address address)
{
	return int3Breakpoints.insert(address).second;
}

bool RemoveInt3BreakpointInternal(Address address)
{
	return int3Breakpoints.erase(address) != 0;
}

bool IsInt3BreakpointAddress(Address address)
{
	return int3Breakpoints.contains(address);
}

bool IsKnownBreakpointAddress(Address address)
{
	return int3ToOriginalByte.contains(address);
}

bool IsMemoryBreakpointAddress(Address address)
{
	auto alignedAddress{ TED::Memory::AlignToPage(address) };
	if (breakpointRanges.empty() || !breakpointRanges.contains(alignedAddress)) {
		return false;
	}

	auto& range{ breakpointRanges[alignedAddress] };
	return std::find(range.begin(), range.end(), address) != range.end();
}

bool IsBreakpointAddress(Address address)
{
	return IsMemoryBreakpointAddress(address) || IsInt3BreakpointAddress(address);
}

void AddMemoryBreakpointAddressInternal(Address address)
{
	auto pageAlignedAddress{ TED::Memory::AlignToPage(address) };

	if (breakpointRanges.find(pageAlignedAddress) == breakpointRanges.end()) {
		breakpointRanges.insert({ pageAlignedAddress, std::vector<Address>() });
	}

	breakpointRanges[pageAlignedAddress].push_back(address);
}

void RemoveMemoryBreakpointAddressInternal(Address address)
{
	auto pageAlignedAddress{ TED::Memory::AlignToPage(address) };

	breakpointRanges[pageAlignedAddress].erase(std::remove(
		breakpointRanges[pageAlignedAddress].begin(), breakpointRanges[pageAlignedAddress].end(), address),
		breakpointRanges[pageAlignedAddress].end());
	if (breakpointRanges[pageAlignedAddress].size() == 0) {
		breakpointRanges.erase(pageAlignedAddress);
	}
}

const std::vector<Address>& GetMemoryBreakpointAddressesForPage(Address address)
{
	auto alignedAddress{ TED::Memory::AlignToPage(address) };
	auto range{ breakpointRanges.find(alignedAddress) };
	if (range == breakpointRanges.end()) {
		static std::vector<Address> emptyRange{};
		return emptyRange;
	}

	return range->second;
}

bool EnableMemoryBreakpoint(Address address)
{
	MEMORY_BASIC_INFORMATION memoryInfo{};

	VirtualQuery(reinterpret_cast<LPCVOID>(address), &memoryInfo, sizeof(MEMORY_BASIC_INFORMATION));
	return TED::Memory::SetPagePermissions(reinterpret_cast<Address>(memoryInfo.BaseAddress),
		memoryInfo.RegionSize, memoryInfo.AllocationProtect | PAGE_GUARD);
}

bool DisableMemoryBreakpoint(Address address)
{
	MEMORY_BASIC_INFORMATION memoryInfo{};

	VirtualQuery(reinterpret_cast<LPCVOID>(address), &memoryInfo, sizeof(MEMORY_BASIC_INFORMATION));
	return TED::Memory::SetPagePermissions(reinterpret_cast<Address>(memoryInfo.BaseAddress),
		memoryInfo.RegionSize, memoryInfo.AllocationProtect & ~PAGE_GUARD);
}

bool SetMemoryBreakpoint(Address address, bool withCallStack, bool isImmediate)
{
	if (IsBreakpointAddress(address)) {
		return true;
	}

	AddMemoryBreakpointAddressInternal(address);
	if (withCallStack) {
		EnableCallStack(address);
	}
	if (isImmediate) {
		AddImmediateBreakpoint(address);
	}

	auto result{ EnableMemoryBreakpoint(address) };
	if (!result) {
		UnsetMemoryBreakpoint(address, withCallStack, isImmediate);
	}

	return result;
}

bool UnsetMemoryBreakpoint(Address address, bool withCallStack, bool isImmediate)
{
	if (!IsMemoryBreakpointAddress(address)) {
		return true;
	}

	auto result{ DisableMemoryBreakpoint(address) };
	if (result) {
		RemoveMemoryBreakpointAddressInternal(address);
		DisableCallStack(address);
		RemoveImmediateBreakpoint(address);
	}

	return result;
}

bool WriteOriginalInstuction(Address address)
{
	std::vector<unsigned char> originalByte{ {int3ToOriginalByte[address]} };
	auto result = TED::Memory::WriteMemory(address, originalByte);

	return result;
}

bool EnableInt3Breakpoint(Address address)
{
	if (!TED::Memory::IsMemoryCommitted(address, sizeof(unsigned char))) {
		return false;
	}

	auto readBytes{ TED::Memory::ReadMemory(address, sizeof(unsigned char)) };
	if (readBytes.size() == 0) {
		return false;
	}

	unsigned char originalByte{ readBytes[0] };;
	int3ToOriginalByte[address] = originalByte;

	std::vector<unsigned char> int3{ {0xCC} };
	auto result{ TED::Memory::WriteMemory(address, int3) };

	return result;
}

bool DisableInt3Breakpoint(Address address)
{
	auto result{ WriteOriginalInstuction(address) };

	// Keep the original byte in case another thread is calling the
	// function when the breakpoint gets disabled.
	
	// int3ToOriginalByte.erase(address);

	return result;
}

bool SetInt3Breakpoint(Address address, bool withCallStack, bool isImmediate)
{
	if (IsBreakpointAddress(address)) {
		return true;
	}

	AddInt3BreakpointInternal(address);
	if (withCallStack) {
		EnableCallStack(address);
	}
	if (isImmediate) {
		AddImmediateBreakpoint(address);
	}

	auto result{ EnableInt3Breakpoint(address) };
	if (!result) {
		UnsetInt3Breakpoint(address, withCallStack, isImmediate);
	}

	return result;
}

bool UnsetInt3Breakpoint(Address address, bool withCallStack, bool isImmediate)
{
	if (!IsInt3BreakpointAddress(address)) {
		return true;
	}

	auto result{ DisableInt3Breakpoint(address) };
	if (result) {
		RemoveInt3BreakpointInternal(address);
		DisableCallStack(address);
		RemoveImmediateBreakpoint(address);
	}

	return result;
}

bool UnsetBreakpoint(Address address, bool withCallStack, bool isImmediate)
{
	if (IsMemoryBreakpointAddress(address)) {
		return UnsetMemoryBreakpoint(address, withCallStack, isImmediate);
	}
	if (IsInt3BreakpointAddress(address)) {
		return UnsetInt3Breakpoint(address, withCallStack, isImmediate);
	}

	return false;
}

bool UnsetAllBreakpointsInModule(std::string moduleName)
{
	std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(),
		[](unsigned char c) { return std::tolower(c); });

	auto modules{ TED::Process::GetModules() };
	auto moduleInfo = std::find_if(modules.begin(), modules.end(),
		[&](TED::Process::Module& info) {
			std::transform(info.name.begin(), info.name.end(), info.name.begin(),
				[](unsigned char c) { return std::tolower(c); });
			return moduleName == info.name;
	});

	if (moduleInfo == modules.end()) {
		return false;
	}

	auto startAddress = moduleInfo->baseAddress;
	auto endAddress = static_cast<Address>(startAddress + moduleInfo->size);

	for (const auto& int3Breakpoint : int3Breakpoints) {
		if (int3Breakpoint >= startAddress && int3Breakpoint <= endAddress) {
			UnsetInt3Breakpoint(int3Breakpoint, true, true);
		}
	}

	auto alignedAddress = TED::Memory::AlignToPage(startAddress);
	while (startAddress < endAddress) {
		if (breakpointRanges.contains(alignedAddress)) {
			auto memoryBreakpoints = breakpointRanges[alignedAddress];
			for (const auto& memoryBreakpoint : memoryBreakpoints) {
				UnsetMemoryBreakpoint(memoryBreakpoint, true, true);
			}
		}

		startAddress += TED::Memory::PAGE_SIZE;
		alignedAddress = TED::Memory::AlignToPage(startAddress);
	}


	return true;
}

std::vector<STACKFRAME64> GetCallStack(Address address, CONTEXT* context)
{
	if (!IsCallStackBreakpoint(brokenAddress)) {
		return std::vector<STACKFRAME64>{};
	}

	CONTEXT localContext = *context;

	std::vector<STACKFRAME64> stackFrames{};
	STACKFRAME64 stackFrame{};
	auto maxFrames{ 16 };

	stackFrame.AddrPC.Mode = AddrModeFlat;
	stackFrame.AddrFrame.Mode = AddrModeFlat;
	stackFrame.AddrStack.Mode = AddrModeFlat;

#ifdef _M_IX86
	auto machineType{ IMAGE_FILE_MACHINE_I386 };
	stackFrame.AddrPC.Offset = context->Eip;
	stackFrame.AddrFrame.Offset = context->Ebp;
	stackFrame.AddrStack.Offset = context->Esp;
#elif defined _M_AMD64
	auto machineType{ IMAGE_FILE_MACHINE_AMD64 };
	stackFrame.AddrPC.Offset = context->Rip;
	stackFrame.AddrFrame.Offset = context->Rbp;
	stackFrame.AddrStack.Offset = context->Rsp;
#else
	#error "Unsupported platform"
#endif

	for (auto i{ 0 }; i < maxFrames; i++)
	{
		auto result{ StackWalk64(machineType, GetCurrentProcess(), GetCurrentThread(), &stackFrame,
			(machineType == IMAGE_FILE_MACHINE_I386 ? nullptr : &localContext),
			nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr) };

		if (!result)
		{
			break;
		}

		stackFrames.push_back(stackFrame);
	}

	return stackFrames;
}

void EnqueueBreakpointEvent(EXCEPTION_POINTERS* exceptionInfo)
{
	constexpr size_t MAX_QUEUE_SIZE = (2 << 22);

	if (breakpointEvents.size_approx() < MAX_QUEUE_SIZE) {
		auto callStack{ GetCallStack(brokenAddress, exceptionInfo->ContextRecord) };
		breakpointEvents.enqueue({ *exceptionInfo->ContextRecord, brokenAddress,
			reinterpret_cast<Address>(exceptionInfo->ExceptionRecord->ExceptionAddress),
			callStack, GetCurrentProcessId(), GetCurrentThreadId() });
	}
}

void ReenableMemoryBreakpoints()
{
	if (!breakpointRanges.empty()) {
		auto breakpoints{ GetMemoryBreakpointAddressesForPage(brokenAddress) };
		for (const auto& breakpoint : breakpoints) {
			EnableMemoryBreakpoint(breakpoint);
		}
	}
}

bool IsInAutoDisableBreakpointMode()
{
	return autoDisableMode;
}

void EnableAutoDisableBreakpointMode()
{
	autoDisableMode = true;
}

void DisableAutoDisableBreakpointMode()
{
	autoDisableMode = false;
}

LONG WINAPI BreakpointHandler(EXCEPTION_POINTERS* exceptionInfo)
{
	if (exceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {

		auto exceptionAddress = reinterpret_cast<Address>(
			exceptionInfo->ExceptionRecord->ExceptionAddress);

		if ((exceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) &&
			!IsInt3BreakpointAddress(exceptionAddress)) {

			ReenableMemoryBreakpoints();

			if (IsKnownBreakpointAddress(exceptionAddress)) {

				WriteOriginalInstuction(brokenAddress);

				return EXCEPTION_CONTINUE_EXECUTION;
			}

			return EXCEPTION_CONTINUE_SEARCH;
		}

		if (IsImmediateBreakpoint(exceptionAddress)) {
			EnqueueBreakpointEvent(exceptionInfo);
		}

		WriteOriginalInstuction(exceptionAddress);

		exceptionInfo->ContextRecord->EFlags |= 0x100;
		brokenAddress = exceptionAddress;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (exceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {

		exceptionInfo->ContextRecord->EFlags |= 0x100;
		brokenAddress = reinterpret_cast<Address>(exceptionInfo->ExceptionRecord->ExceptionAddress);

		if (IsImmediateBreakpoint(brokenAddress)) {
			EnqueueBreakpointEvent(exceptionInfo);
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (exceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

		if (!IsImmediateBreakpoint(brokenAddress)) {
			if (IsMemoryBreakpointAddress(brokenAddress) || IsInt3BreakpointAddress(brokenAddress)) {
				EnqueueBreakpointEvent(exceptionInfo);
			}

			if (IsInAutoDisableBreakpointMode()) {
				UnsetBreakpoint(brokenAddress, true, true);
			}
			else if (IsInt3BreakpointAddress(brokenAddress)) {
				EnableInt3Breakpoint(brokenAddress);
			}
		}

		ReenableMemoryBreakpoints();

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

}
}