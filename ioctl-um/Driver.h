#include <stdio.h>
#include <Windows.h>
#include <winioctl.h>
#include <string>
#include <Winternl.h>
#include <iostream>
#include <fstream>
#include <assert.h>
#pragma comment(lib, "ntdll.lib")
#pragma warning(disable: 4996)
#define IOCTL_READ_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x999, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x998, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define DRIVER_NAME L"\\\\.\\KRPM_Driver"

EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);

//#pragma comment(lib, "MoaRpm.lib")

class MoaRpm {
public:
	static enum MOA_MODE {
		STANDARD,
		NTDLL,
		KERNEL
	};
private:
	DWORD pID;
	HANDLE hProcess;
	MOA_MODE mode = MOA_MODE::STANDARD;
	BOOL load_driver(std::string TargetDriver, std::string TargetServiceName, std::string TargetServiceDesc);

	BOOL delete_service(std::string TargetServiceName);
	std::string exePath();
	bool isElevated();

	bool isTestMode();
	const static unsigned char rawDriver[8304];
	void init(DWORD pID, MOA_MODE AccessMode);
public:
	MoaRpm(DWORD pID, MOA_MODE AccessMode);
	MoaRpm(const char* windowname, MOA_MODE AccessMode);
	~MoaRpm();
	void readRaw(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
	bool writeRaw(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);

	template <class cData>
	cData read(DWORD_PTR Address);

	template <class cData>
	bool write(DWORD_PTR Address, cData buffer);

	template<class CharT = char>
	std::basic_string<CharT> readString(DWORD_PTR address, size_t max_length = 256);
};

template <class cData>
cData MoaRpm::read(DWORD_PTR Address) {
	cData B;
	SIZE_T bytesRead;
	this->readRaw((LPCVOID)Address, &B, sizeof(B), &bytesRead);
	return B;
}

template <class cData>
bool MoaRpm::write(DWORD_PTR Address, cData buffer) {
	SIZE_T bytesRead;
	this->writeRaw((LPCVOID)Address, &buffer, sizeof(cData), &bytesRead);
	return true;
}

template<class CharT>
std::basic_string<CharT> MoaRpm::readString(DWORD_PTR address, size_t max_length)
{
	std::basic_string<CharT> str(max_length, CharT());
	SIZE_T bytesRead;
	this->readRaw((LPVOID)address, &str[0], sizeof(CharT) * max_length, &bytesRead);
	auto it = str.find(CharT());
	if (it == str.npos) str.clear();
	else str.resize(it);
	return str;
}