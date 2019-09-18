#include "CRT.h"

HANDLE ProcessHeap = NULL;

NTSTATUS InitAllocations() {

	ProcessHeap = GetProcessHeap();
	if (!ProcessHeap) {

		return NTSTATUS_FROM_WIN32(GetLastError());
	}

	return STATUS_SUCCESS;
}

__declspec(allocator,restrict) void * __cdecl malloc(size_t _Size) {
	
	return HeapAlloc(ProcessHeap, 0, _Size);
}

void __cdecl free(void * _Block) {

	if (_Block) {

		HeapFree(ProcessHeap, 0, _Block);
	}
}