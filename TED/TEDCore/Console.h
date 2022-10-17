#pragma once

#include <string_view>

namespace TED
{
namespace Console
{

bool CreateConsole();
bool DestroyConsole();

void EnableLogging();
void DisableLogging();
bool IsLoggingEnabled();

void LogInternal(std::string_view message);

}
}
