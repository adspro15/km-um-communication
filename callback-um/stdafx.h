#pragma once
#include <Windows.h>
#include <ntstatus.h>
#include <malloc.h>
#include <subauth.h>
#include <intrin.h>
#include "CRT/CRT.h"

#pragma region Memory

/***/#pragma function(memcmp)
/***/#pragma function(memset)
/***/#pragma function(memcpy)
/***/#pragma function(memmove)

#pragma endregion



#pragma region String

/***/#pragma function(strlen)
/***/#pragma function(strcmp)
/***/#pragma function(strcat)
/***/#pragma function(strcpy)

#pragma endregion



#pragma region WString

/***/#pragma function(wcslen)
/***/#pragma function(wcscmp)
/***/#pragma function(wcscat)
/***/#pragma function(wcscpy)

#pragma endregion