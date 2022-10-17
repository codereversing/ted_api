#pragma once

#include <string>
#include <vector>

#include <Windows.h>
#include <DbgHelp.h>

#include "CommonTypes.h"

#include <concurrentqueue/concurrentqueue.h>

namespace TED
{
namespace Breakpoint
{

typedef struct {
	CONTEXT context;
	Address source_address;
	Address destination_address;
	std::vector<STACKFRAME64> stackFrames;
	unsigned int processId;
	unsigned int threadId;
} BreakpointEvent;

extern moodycamel::ConcurrentQueue<BreakpointEvent> breakpointEvents;

bool SetMemoryBreakpoint(Address address, bool withCallStack, bool isImmediate);
bool UnsetMemoryBreakpoint(Address address, bool withCallStack, bool isImmediate);

bool SetInt3Breakpoint(Address address, bool withCallStack, bool isImmediate);
bool UnsetInt3Breakpoint(Address address, bool withCallStack, bool isImmediate);

bool UnsetBreakpoint(Address address, bool withCallStack, bool isImmediate);
bool UnsetAllBreakpointsInModule(std::string moduleName);

void EnableAutoDisableBreakpointMode();
void DisableAutoDisableBreakpointMode();

LONG WINAPI BreakpointHandler(EXCEPTION_POINTERS* exceptionInfo);

}
}