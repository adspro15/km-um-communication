#pragma once
#include <windows.h>
#include <iostream>

ULONG PID;
ULONG64 baseaddr = NULL;
HANDLE hMapFileW;
HANDLE hMapFileR;
HANDLE g_hMutex;

HANDLE SharedEvent_dataarv;
HANDLE SharedEvent_trigger;
HANDLE SharedEvent_ready2read;
