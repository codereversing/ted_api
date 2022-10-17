#include "Console.h"

#include <iostream>

#include <Windows.h>

namespace TED
{
namespace Console
{

static bool loggingEnabled{};
static bool consoleAllocated{};

bool CreateConsole()
{
	auto result{ AllocConsole() };
	if (result) {
		FILE* stream{};
		(void)freopen_s(&stream, "CONOUT$", "w", stdout);
		(void)freopen_s(&stream, "CONOUT$", "w", stderr);
		SetConsoleTitle(L"Console");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
			FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		consoleAllocated = true;
	}
	else if (GetLastError() == ERROR_ACCESS_DENIED) {
		result = true;
	}


	return result;
}

bool DestroyConsole()
{
	if (!consoleAllocated) {
		return true;
	}

	return FreeConsole();
}

void EnableLogging()
{
	loggingEnabled = true;
}

void DisableLogging()
{
	loggingEnabled = false;
}

bool IsLoggingEnabled()
{
	return loggingEnabled;
}

void LogInternal(std::string_view message)
{
	if (IsLoggingEnabled()) {
		std::cerr << message << std::endl;
	}
}

}
}
