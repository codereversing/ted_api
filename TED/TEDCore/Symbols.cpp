#pragma comment(lib, "Dbghelp.lib")

#include "Symbols.h"

#include <array>
#include <atomic>

#include <Windows.h>
#include <DbgHelp.h>

namespace TED
{
namespace Symbols
{

static std::atomic_bool symbolsEnabled{};

bool EnableSymbols(std::string_view path)
{
	if (symbolsEnabled) {
		return true;
	}

	SymSetOptions(SYMOPT_UNDNAME);

	auto result{ SymInitialize(GetCurrentProcess(), nullptr, TRUE) };

	if (!path.empty()) {
		std::array<char, MAX_PATH * 8> symbolPaths{};
		result &=
			SymGetSearchPath(GetCurrentProcess(), symbolPaths.data(), static_cast<DWORD>(symbolPaths.size()));
		if (result) {
			std::string foundPathsStr{ symbolPaths.data() };
			if (!foundPathsStr.ends_with(";")) {
				foundPathsStr += ";";
			}

			foundPathsStr += path;
			result &= SymSetSearchPath(GetCurrentProcess(), foundPathsStr.c_str());
		}
	}

	symbolsEnabled = result;

	return result;
}

bool DisableSymbols()
{
	if (!symbolsEnabled) {
		return true;
	}

	auto result{ SymCleanup(GetCurrentProcess()) };
	symbolsEnabled = !result;

	return result;
}

std::string SymbolNameFromAddress(Address address)
{
	if (!symbolsEnabled) {
		return std::string{};
	}

	std::array<char, sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)> pBuffer{};
	auto symbolInfo{ reinterpret_cast<SYMBOL_INFO*>(pBuffer.data()) };

	symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
	symbolInfo->MaxNameLen = MAX_SYM_NAME;

	DWORD64 dwDisplacement{};
	auto result{ SymFromAddr(GetCurrentProcess(), address, &dwDisplacement, symbolInfo) };
	if (!result) {
		return std::string{};
	}

	return std::string{ symbolInfo->Name, symbolInfo->NameLen };
}

Address SymbolAddressFromName(std::string_view name)
{
	if (!symbolsEnabled) {
		return 0;
	}

	std::array<char, sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)> pBuffer{};
	auto symbolInfo{ reinterpret_cast<SYMBOL_INFO*>(pBuffer.data()) };

	symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
	symbolInfo->MaxNameLen = MAX_SYM_NAME;

	auto result{ SymFromName(GetCurrentProcess(), name.data(), symbolInfo) };
	if (!result) {
		return 0;
	}

	return symbolInfo->Address;
}

}
}
