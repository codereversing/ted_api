#include "Memory.h"

#include <atomic>
#include <cstring>

#include <Windows.h>

namespace TED
{
namespace Memory
{

static bool unsafeMemoryMode{};

Address AlignToPage(Address address)
{
	return ((address)+PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

bool IsMemoryCommitted(Address address, size_t size)
{
	if (unsafeMemoryMode) {
		return true;
	}

	MEMORY_BASIC_INFORMATION memoryInfo{};
	auto result{ VirtualQuery(reinterpret_cast<LPCVOID>(address), &memoryInfo, sizeof(MEMORY_BASIC_INFORMATION)) };

	return (memoryInfo.RegionSize >= size) && (memoryInfo.State & MEM_COMMIT);
}

unsigned long GetPagePermissions(Address address)
{
	MEMORY_BASIC_INFORMATION memoryInfo{};
	VirtualQuery(reinterpret_cast<LPCVOID>(address), &memoryInfo, sizeof(MEMORY_BASIC_INFORMATION));

	return static_cast<unsigned long>(memoryInfo.AllocationProtect);
}

bool SetPagePermissions(Address address, size_t size, unsigned long newProtections, unsigned long& oldProtections)
{
	if (unsafeMemoryMode) {
		return true;
	}

	auto result{ VirtualProtect(reinterpret_cast<LPVOID>(address), size, newProtections,
		&oldProtections) };

	return result;

}

bool SetPagePermissions(Address address, size_t size, unsigned long newProtections)
{
	DWORD oldProtections{};
	return SetPagePermissions(address, size, newProtections, oldProtections);
}

std::vector<unsigned char> ReadMemory(Address address, size_t size)
{
	if (!IsMemoryCommitted(address, size)) {
		return std::vector<unsigned char>{};
	}

	std::vector<unsigned char> bytes(size);
	std::memcpy(bytes.data(), reinterpret_cast<const void*>(address), size);

	return bytes;
}

bool FlushInstructionCache(Address address)
{
	if (unsafeMemoryMode) {
		return true;
	}

	return ::FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), PAGE_SIZE);
}

bool WriteMemory(Address address, std::vector<unsigned char>& bytes)
{
	if (!IsMemoryCommitted(address, bytes.size())) {
		return false;
	}

	DWORD oldProtections{};
	auto result{ SetPagePermissions(address, bytes.size(), PAGE_EXECUTE_READWRITE, oldProtections) };
	if (result) {

		std::memcpy(reinterpret_cast<void*>(address), bytes.data(), bytes.size());

		// Multiple threads can set the page permission simlutaneously, so don't set it back to prevent
		// access violations.
		
		//result &= SetPagePermissions(address, bytes.size(), oldProtections);

#if !defined(_M_IX86) && !defined(_M_AMD64)
		FlushInstructionCache(address);
#endif

	}

	return result;
}

void EnableUnsafeMemoryMode()
{
	unsafeMemoryMode = true;
}

void DisableUnsafeMemoryMode()
{
	unsafeMemoryMode = false;
}

}
}
