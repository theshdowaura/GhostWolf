#pragma once
#include <minwindef.h>

BOOL FindProcessPID(LPCWSTR processName, DWORD* pid, HANDLE* hProcess);
BOOL GetRemoteModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName, uintptr_t& baseAddress, DWORD* moduleSize);