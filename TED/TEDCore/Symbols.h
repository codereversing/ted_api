#pragma once

#include <string>
#include <string_view>

#include "CommonTypes.h"

namespace TED
{
namespace Symbols
{

bool EnableSymbols(std::string_view path);
bool DisableSymbols();
std::string SymbolNameFromAddress(Address address);
Address SymbolAddressFromName(std::string_view name);

}
}
