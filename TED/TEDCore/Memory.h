#pragma once

#include <vector>

#include "CommonTypes.h"

namespace TED
{
namespace Memory
{

constexpr unsigned long long PAGE_SIZE = 4096;

Address AlignToPage(Address address);

bool IsMemoryCommitted(Address address, size_t size);
unsigned long GetPagePermissions(Address address);
bool SetPagePermissions(Address address, size_t size, unsigned long newProtections, unsigned long& oldProtections);
bool SetPagePermissions(Address address, size_t size, unsigned long newProtections);

std::vector<unsigned char> ReadMemory(Address address, size_t size);
bool WriteMemory(Address address, std::vector<unsigned char>& bytes);

void EnableUnsafeMemoryMode();
void DisableUnsafeMemoryMode();

}
}
