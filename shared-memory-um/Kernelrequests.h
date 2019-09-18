#pragma once
#include <iostream>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include "KernelHelpers.h"
#include "Structs.h"
#include <stdio.h>
#include <aclapi.h>

DWORD dwRes;
SECURITY_ATTRIBUTES sa;
PSECURITY_DESCRIPTOR pSD = NULL;
SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
PACL pAcl = NULL;
PSID pEveryoneSID = NULL;
EXPLICIT_ACCESS ea[1];

class Kernelrequests
{
public:
	DWORD_PTR FindProcessId(const std::string& processName)
	{
		PROCESSENTRY32 processInfo;
		processInfo.dwSize = sizeof(processInfo);

		HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (processesSnapshot == INVALID_HANDLE_VALUE)
			return 0;

		Process32First(processesSnapshot, &processInfo);
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}

		while (Process32Next(processesSnapshot, &processInfo))
		{
			if (!processName.compare(processInfo.szExeFile))
			{
				CloseHandle(processesSnapshot);
				return processInfo.th32ProcessID;
			}
		}

		CloseHandle(processesSnapshot);
		return 0;
	}

	template<typename T>
	bool Write(UINT_PTR WriteAddress, const T& value)
	{
		return WriteVirtualMemoryRaw(WriteAddress, (UINT_PTR)&value, sizeof(T));
	}

	bool WriteVirtualMemoryRaw(UINT_PTR WriteAddress, UINT_PTR SourceAddress, SIZE_T WriteSize)
	{
		auto Write_memoryst = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
		char str[8];
		strcpy_s(str, "Write");
		RtlCopyMemory(Write_memoryst, str, strlen(str) + 1);

		UnmapViewOfFile(Write_memoryst);

		WaitForSingleObject(SharedEvent_dataarv, INFINITE);

		KM_WRITE_REQUEST* Sent_struct = (KM_WRITE_REQUEST*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, sizeof(KM_WRITE_REQUEST));

		if (!Sent_struct) {
			return false;
		}

		KM_WRITE_REQUEST  WriteRequest;
		WriteRequest.ProcessId = PID;
		WriteRequest.ProcessidOfSource = GetCurrentProcessId(); // gets our program PID.
		WriteRequest.TargetAddress = WriteAddress;
		WriteRequest.SourceAddress = SourceAddress;
		WriteRequest.Size = WriteSize;

		KM_WRITE_REQUEST* test_ptr = &WriteRequest;
		if (0 == memcpy(Sent_struct, test_ptr, sizeof(KM_WRITE_REQUEST))) {
			return false;
		}

		UnmapViewOfFile(Sent_struct);

		WaitForSingleObject(SharedEvent_trigger, INFINITE);
		ResetEvent(SharedEvent_trigger);
		return true;
	}

	template <typename type>
	type Read(UINT_PTR ReadAddress)
	{
		auto Read_memoryst = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
		char str[8];
		strcpy_s(str, "Read");
		RtlCopyMemory(Read_memoryst, str, strlen(str) + 1);

		UnmapViewOfFile(Read_memoryst);

		WaitForSingleObject(SharedEvent_dataarv, INFINITE);

		KM_READ_REQUEST* Sent_struct = (KM_READ_REQUEST*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, sizeof(KM_READ_REQUEST));

		if (!Sent_struct) {
			return false;
		}

		KM_READ_REQUEST ReadRequest{};

		type response{};

		ReadRequest.ProcessId = PID;
		ReadRequest.SourceAddress = ReadAddress;
		ReadRequest.Size = sizeof(type);
		ReadRequest.Output = &response;

		KM_READ_REQUEST* test_ptr = &ReadRequest;
		if (0 == memcpy(Sent_struct, test_ptr, sizeof(KM_READ_REQUEST))) {
			return 1;
		}

		UnmapViewOfFile(Sent_struct);

		WaitForSingleObject(SharedEvent_ready2read, INFINITE);

		KM_READ_REQUEST* Read_struct = (KM_READ_REQUEST*)MapViewOfFile(hMapFileR, FILE_MAP_READ, 0, 0, sizeof(KM_READ_REQUEST));
		if (!Read_struct)
		{
			return 0;
		}

		type Returnval = ((type)Read_struct->Output);

		UnmapViewOfFile(Read_struct);
		WaitForSingleObject(SharedEvent_trigger, INFINITE);
		ResetEvent(SharedEvent_trigger);
		return Returnval;
	}

	bool ClearMmunloadedDrivers() {
		auto Clearmm_memoryst = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
		if (!hMapFileW || hMapFileW == INVALID_HANDLE_VALUE) {
			printf("MapViewOfFile(Clearmm_memoryst) fail! Error: %u\n", GetLastError());
			return false;
		}
		char str[10];
		strcpy_s(str, "Clearmm");
		if (0 == RtlCopyMemory(Clearmm_memoryst, str, strlen(str) + 1)) {
			printf("RtlCopyMemory(Clearmm_memoryst) fail! Error: %u\n", GetLastError());
			return false;
		}
		printf("message has been sent to kernel [Clearmm]! \n");
		UnmapViewOfFile(Clearmm_memoryst);

		WaitForSingleObject(SharedEvent_ready2read, INFINITE);

		auto pBuf = (char*)MapViewOfFile(hMapFileR, FILE_MAP_READ, 0, 0, 4096);
		if (!pBuf)
		{
			printf("OpenFileMappingA(read) fail! Error: %u\n", GetLastError());
			return 0;
		}

		printf("Data: %s\n", pBuf);
		UnmapViewOfFile(pBuf);
		return true;
	}

	bool ClearPIDCache() {
		auto ClearPIDCache_mem = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
		if (!hMapFileW || hMapFileW == INVALID_HANDLE_VALUE) {
			printf("MapViewOfFile(ClearPIDCache_mem) fail! Error: %u\n", GetLastError());
			return false;
		}
		char str1[11];
		strcpy_s(str1, "Clearpid");
		if (0 == RtlCopyMemory(ClearPIDCache_mem, str1, strlen(str1) + 1)) {
			printf("RtlCopyMemory(ClearPIDCache_mem) fail! Error: %u\n", GetLastError());
			return false;
		}
		printf("message has been sent to kernel [ClearPIDCache_mem]! \n");
		UnmapViewOfFile(ClearPIDCache_mem);

		WaitForSingleObject(SharedEvent_ready2read, INFINITE);

		auto pBuf = (char*)MapViewOfFile(hMapFileR, FILE_MAP_READ, 0, 0, 4096);
		if (!pBuf)
		{
			printf("OpenFileMappingA(read) fail! Error: %u\n", GetLastError());
			return 0;
		}

		printf("Data: %s\n", pBuf);
		UnmapViewOfFile(pBuf);
		return true;
	}

	ULONG64 GetModuleBase(ULONG pid) {

		auto GetModuleBase_msg = (char*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, 4096);
		if (!hMapFileW || hMapFileW == INVALID_HANDLE_VALUE) {
			return 0;
		}
		char str[10];
		strcpy_s(str, "getBase");
		if (0 == RtlCopyMemory(GetModuleBase_msg, str, strlen(str) + 1)) {
			return 0;
		}

		UnmapViewOfFile(GetModuleBase_msg);

		WaitForSingleObject(SharedEvent_dataarv, INFINITE);

		GET_USERMODULE_IN_PROCESS* Sent_struct = (GET_USERMODULE_IN_PROCESS*)MapViewOfFile(hMapFileW, FILE_MAP_WRITE, 0, 0, sizeof(GET_USERMODULE_IN_PROCESS));

		if (!Sent_struct) {
			return 0;
		}

		GET_USERMODULE_IN_PROCESS requestbase;

		requestbase.pid = pid;

		GET_USERMODULE_IN_PROCESS* test_ptr = &requestbase;
		if (0 == memcpy(Sent_struct, test_ptr, sizeof(GET_USERMODULE_IN_PROCESS))) {
			return 0;
		}

		UnmapViewOfFile(Sent_struct);

		WaitForSingleObject(SharedEvent_ready2read, INFINITE);

		GET_USERMODULE_IN_PROCESS* getbase_struct = (GET_USERMODULE_IN_PROCESS*)MapViewOfFile(hMapFileR, FILE_MAP_READ, 0, 0, sizeof(GET_USERMODULE_IN_PROCESS));
		if (!getbase_struct)
		{
			return 0;
		}

		ULONG64 base = NULL;

		base = getbase_struct->BaseAddress;

		UnmapViewOfFile(getbase_struct);

		return base;
	}

	void createSecuritydesc() {
		if (!AllocateAndInitializeSid(
			&SIDAuthWorld,
			1,
			SECURITY_WORLD_RID,
			0, 0, 0, 0, 0, 0, 0,
			&pEveryoneSID))
		{
		}

		ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
		ea[0].grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
		ea[0].grfAccessMode = SET_ACCESS;
		ea[0].grfInheritance = NO_INHERITANCE;
		ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

		dwRes = SetEntriesInAcl(1, ea, NULL, &pAcl);

		pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);

		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = pSD;
		sa.bInheritHandle = FALSE;
	}


	void createConsMenu() {
		static const char* ConHdr = "==================================================\n"
			"|        shared-memory driver by alxbrn          |\n"
			"| Press F8 to open shared memory.                |\n"
			"| Press F6 to write Memory!.					  |\n"
			"| Press F9 to Trigger kernel loop!.              |\n"
			"==================================================\n\n";
		SetConsoleTitleA("shared-memory by alxbrn");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xD);
		printf(ConHdr);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x5);
	}

	void CreateSharedEvents() {
		SharedEvent_dataarv = CreateEventA(&sa, TRUE, FALSE, "Global\\DataArrived");
		if (!SharedEvent_dataarv)
		{
		}

		SharedEvent_trigger = CreateEventA(&sa, TRUE, FALSE, "Global\\trigger");
		if (!SharedEvent_trigger)
		{
		}

		SharedEvent_ready2read = CreateEventA(&sa, TRUE, FALSE, "Global\\ReadyRead");
		if (!SharedEvent_ready2read)
		{
		}
	}

	bool OpenSharedMemory() {
		hMapFileW = OpenFileMappingA(FILE_MAP_WRITE, FALSE, "Global\\SharedMem");
		if (!hMapFileW || hMapFileW == INVALID_HANDLE_VALUE)
		{
			return false;
	}

		hMapFileR = OpenFileMappingA(FILE_MAP_READ, FALSE, "Global\\SharedMem");
		if (!hMapFileR || hMapFileR == INVALID_HANDLE_VALUE)
		{
			return false;
		}
		printf("[Completed] SHared MEmory is available to use !.\n");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xA);
		return true;
	}

	void GetPidNBaseAddr() {
		PID = FindProcessId("dummy.exe");
		std::cout << "PID IS : " << PID << std::endl;

		baseaddr = GetModuleBase(PID);
		std::cout << "base address is : " << std::hex << baseaddr << std::endl;
	}
};
