#include "stdafx.h"
#include "Cse/Cse.h"
#include "CvcCl/Cvc.h"

NTSTATUS
__fastcall
TestThread(
	const pCvcConnection pConnection
) {

	NTSTATUS Status = STATUS_SUCCESS;
	
	char buff[0x100];
	WORD DosSignature = 0;

	sprintf(buff, "%s", __FUNCTION__);
	CseOutputA(buff);

	const PLARGE_INTEGER CvcResults = malloc(sizeof(LARGE_INTEGER) * 1000);

	if (CvcResults) {

		ZeroMemory(CvcResults, sizeof(LARGE_INTEGER) * 1000);

		LARGE_INTEGER Start, End, Elapsed, Freq;
		QueryPerformanceFrequency(&Freq);

		const HANDLE Pid = (HANDLE)GetCurrentProcessId();
		const DWORD64 Ptr = (DWORD64)GetModuleHandleA(NULL);

		for (int i = 0; i < 1000; i++) {

			QueryPerformanceCounter(&Start);

			Status = CvcPostRead(
				pConnection,
				Pid,
				Ptr,
				sizeof(WORD),
				&DosSignature
			);

			QueryPerformanceCounter(&End);
			Elapsed.QuadPart = End.QuadPart - Start.QuadPart;

			Elapsed.QuadPart *= 1000000;
			Elapsed.QuadPart /= Freq.QuadPart;
			CvcResults[i] = Elapsed;
		}

		sprintf(buff, "%s: DosSignature = %x", __FUNCTION__, DosSignature);
		CseOutputA(buff);

		LARGE_INTEGER Min = { .QuadPart = 0xFFFFFFFF };
		LARGE_INTEGER Max = { .QuadPart = 0x0 };
		LARGE_INTEGER Avg = { .QuadPart = 0x0 };

		for (int i = 0; i < 1000; i++) {

			if (Min.QuadPart > CvcResults[i].QuadPart) {

				Min.QuadPart = CvcResults[i].QuadPart;
			}

			if (Max.QuadPart < CvcResults[i].QuadPart) {

				Max.QuadPart = CvcResults[i].QuadPart;
			}

			Avg.QuadPart += CvcResults[i].QuadPart;
		}

		Avg.QuadPart /= 1000;

		sprintf(buff, "%s: Min = %d microseconds", __FUNCTION__, Min.QuadPart);
		CseOutputA(buff);

		sprintf(buff, "%s: Max = %d microseconds", __FUNCTION__, Max.QuadPart);
		CseOutputA(buff);

		sprintf(buff, "%s: Avg = %d microseconds", __FUNCTION__, Avg.QuadPart);
		CseOutputA(buff);

		free(CvcResults);
	}
	
	return STATUS_SUCCESS;
}

int
Main(
	VOID
) {

	NTSTATUS Status = STATUS_SUCCESS;

	if (!NT_SUCCESS(Status = InitCRT())) {

		TerminateProcess((HANDLE)-1, Status);
	}

	if (!NT_SUCCESS(Status = CseCreate())) {

		TerminateProcess((HANDLE)-1, Status);
	}

	if (!NT_SUCCESS(Status = CseOutputA("Hi"))) {

		TerminateProcess((HANDLE)-1, Status);
	}

	if (!NT_SUCCESS(Status = CvcCreate())) {

		TerminateProcess((HANDLE)-1, Status);
	}

	CvcPostHelloWorld(NULL);
	char buff[0x100];
	sprintf(buff, "Status0 = 0x%X", Status);
	CseOutputA(buff);
	
	if (!NT_SUCCESS(Status = CvcSpawnThread(TestThread))) {

		TerminateProcess((HANDLE)-1, Status);
	}

	sprintf(buff, "Status1 = 0x%X", Status);

	CseOutputA(buff);

	WORD DosSignature = 0;

	const PLARGE_INTEGER CvcResults = malloc(sizeof(LARGE_INTEGER) * 1000);
	ZeroMemory(CvcResults, sizeof(LARGE_INTEGER) * 1000);

	LARGE_INTEGER Start, End, Elapsed, Freq;
	QueryPerformanceFrequency(&Freq);

	const HANDLE Pid = (HANDLE)GetCurrentProcessId();
	const DWORD64 Ptr = (DWORD64)GetModuleHandleA(NULL);

	for (int i = 0; i < 1000; i++) {

		QueryPerformanceCounter(&Start);

		Status = CvcPostRead(
			NULL,
			Pid,
			Ptr,
			sizeof(WORD),
			&DosSignature
		);

		QueryPerformanceCounter(&End);
		Elapsed.QuadPart = End.QuadPart - Start.QuadPart;

		Elapsed.QuadPart *= 1000000;
		Elapsed.QuadPart /= Freq.QuadPart;
		CvcResults[i] = Elapsed;
	}

	sprintf(buff, "%s: DosSignature = %x", __FUNCTION__, DosSignature);
	CseOutputA(buff);

	LARGE_INTEGER Min = { .QuadPart = 0xFFFFFFFF };
	LARGE_INTEGER Max = { .QuadPart = 0x0 };
	LARGE_INTEGER Avg = { .QuadPart = 0x0 };

	for (int i = 0; i < 1000; i++) {

		if (Min.QuadPart > CvcResults[i].QuadPart) {

			Min.QuadPart = CvcResults[i].QuadPart;
		}

		if (Max.QuadPart < CvcResults[i].QuadPart) {

			Max.QuadPart = CvcResults[i].QuadPart;
		}

		Avg.QuadPart += CvcResults[i].QuadPart;
	}

	Avg.QuadPart /= 1000;

	sprintf(buff, "%s: Min = %d microseconds",__FUNCTION__, Min.QuadPart);
	CseOutputA(buff);

	sprintf(buff, "%s: Max = %d microseconds", __FUNCTION__, Max.QuadPart);
	CseOutputA(buff);

	sprintf(buff, "%s: Avg = %d microseconds", __FUNCTION__, Avg.QuadPart);
	CseOutputA(buff);
	
	free(CvcResults);
	CvcWaitConnections();
	CvcTerminate();

	if (!NT_SUCCESS(Status = CseWaitInput())) {

		TerminateProcess((HANDLE)-1, Status);
	}

	if (!NT_SUCCESS(Status = CseClear())) {

		TerminateProcess((HANDLE)-1, Status);
	}

	TerminateProcess((HANDLE)-1, 0);

	return 0;
}
