#include <iostream>
#include <windows.h>
#include "Kernelrequests.h"
#include "KernelHelpers.h"
#include <tchar.h>

Kernelrequests* pMem;

void sendrequests() {
	// pMem->Read<int>(0x123456);
	// pMem->Write<int>(0x123456,55);

	pMem->ClearMmunloadedDrivers();
	pMem->ClearPIDCache();
}

void stoploop() {
	auto stopmsg = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);

	char stopmms[8];
	strcpy_s(stopmms, "Stop");

	RtlCopyMemory(stopmsg, stopmms, strlen(stopmms) + 1);

	printf("message has been sent to kernel [Stop]! \n");

	FlushViewOfFile(stopmsg, 4096);
	UnmapViewOfFile(stopmsg);
}

int main() {
	pMem->createConsMenu();

	pMem->GetPidNBaseAddr();

	pMem->createSecuritydesc();

	pMem->CreateSharedEvents();

	while (true)
	{
		if (GetAsyncKeyState(VK_F8))
		{
			if (!pMem->OpenSharedMemory()) {
				printf("OpenSharedMemory returned false.[failed]\n");
			}
			Sleep(100);
		}
		else if (GetAsyncKeyState(VK_F6)) {
			sendrequests();
			printf("[Completed] sent sendrequests msg to kernel![sendrequests] \n");
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xA);
			Sleep(100);
		}
		else if (GetAsyncKeyState(VK_F5)) {
			stoploop();
			Sleep(100);
		}
		Sleep(1);
	}

	system("pause");
}
