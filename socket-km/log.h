#pragma once
#include <ntddk.h>

template <typename... Args>
void log(const char* format, Args... args)
{
	DbgPrintEx(0, 0, "[alxbrn_driver] ");
	DbgPrintEx(0, 0, format, args...);
	DbgPrintEx(0, 0, "\n");
}