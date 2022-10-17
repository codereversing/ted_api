#include <Windows.h>

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow)
{
    return reinterpret_cast<INT>(LoadLibraryA);
}