#include "../stdafx.h"
#include "Cse.h"

HANDLE hCseOutput = INVALID_HANDLE_VALUE;
HANDLE hCseInput = INVALID_HANDLE_VALUE;


BOOLEAN
CsepConsoleCreated(
	VOID
) {

	return 
		hCseOutput != INVALID_HANDLE_VALUE &&
		hCseInput != INVALID_HANDLE_VALUE;
}

NTSTATUS
CseCreate(
	VOID
) {

	if (CsepConsoleCreated()) {

		return STATUS_ALREADY_COMPLETE;
	}

	if (!AllocConsole()) {

		return NTSTATUS_FROM_WIN32(GetLastError());
	}

	hCseOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	hCseInput = GetStdHandle(STD_INPUT_HANDLE);

	if (!CsepConsoleCreated()) {

		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS
CseTerminate(
	VOID
) {

	hCseOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	hCseInput = GetStdHandle(STD_INPUT_HANDLE);

	if (!CsepConsoleCreated()) {

		return STATUS_ALREADY_COMPLETE;
	}

	if (!FreeConsole()) {

		return NTSTATUS_FROM_WIN32(GetLastError());
	}

	hCseOutput = hCseInput = INVALID_HANDLE_VALUE;

	return STATUS_SUCCESS;
}

NTSTATUS
CseClear(
	VOID
) {

	if (!CsepConsoleCreated()) {

		return STATUS_UNSUCCESSFUL;
	}

	CONSOLE_SCREEN_BUFFER_INFO CseScreenInfo = { 0 };

	if (!GetConsoleScreenBufferInfo(hCseOutput,&CseScreenInfo)) {

		return NTSTATUS_FROM_WIN32(GetLastError());
	}

	COORD TopLeft = { 0 };
	DWORD Written = 0;

	if (!FillConsoleOutputCharacterA(
		hCseOutput,
		'\0',
		CseScreenInfo.dwSize.Y * CseScreenInfo.dwSize.X,
		TopLeft,
		&Written)) {

		return NTSTATUS_FROM_WIN32(GetLastError());
	}

	if (!SetConsoleCursorPosition(hCseOutput, TopLeft)) {
		return NTSTATUS_FROM_WIN32(GetLastError());
	}

	return STATUS_SUCCESS;
}

NTSTATUS
CseOutputA(
	const char* Text
) {

	if (hCseOutput == INVALID_HANDLE_VALUE) {

		return STATUS_INVALID_HANDLE;
	}

	if (!Text) {

		return STATUS_INVALID_PARAMETER;
	}

	DWORD ToWrite = 0;
	PVOID Buffer = NULL;

	__try {

		ToWrite = (DWORD)(strlen(Text) + 1);
		Buffer = alloca((ToWrite + 1) * sizeof(char));
		strcpy(Buffer, Text);
		strcat(Buffer, "\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		return GetExceptionCode();
	}

	DWORD CharsWritten = 0;

	if (!WriteConsoleA(hCseOutput, Buffer, ToWrite, &CharsWritten, NULL)) {

		return NTSTATUS_FROM_WIN32(GetLastError());
	}

	return STATUS_SUCCESS;
}

NTSTATUS
CseOutputW(
	const wchar_t* Text
) {

	if (hCseOutput == INVALID_HANDLE_VALUE) {

		return STATUS_INVALID_HANDLE;
	}

	if (!Text) {

		return STATUS_INVALID_PARAMETER;
	}

	DWORD ToWrite = 0;
	PVOID Buffer = NULL;

	__try {

		ToWrite = (DWORD)(wcslen(Text) + 1);
		Buffer = alloca((ToWrite + 1) * sizeof(wchar_t));
		wcscpy(Buffer, Text);
		wcscat(Buffer, L"\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		return GetExceptionCode();
	}

	DWORD CharsWritten = 0;

	if (!WriteConsoleW(hCseOutput, Buffer, ToWrite, &CharsWritten, NULL)) {

		return NTSTATUS_FROM_WIN32(GetLastError());
	}

	return STATUS_SUCCESS;
}

NTSTATUS
CseWaitInput(
	VOID
) {

	if (hCseInput == INVALID_HANDLE_VALUE) {

		return STATUS_INVALID_HANDLE;
	}

	DWORD read;
	wchar_t buff[256];
	ZeroMemory(buff, sizeof(buff));

	if (!ReadConsoleW(hCseInput, buff, sizeof(buff), &read, NULL)) {

		return NTSTATUS_FROM_WIN32(GetLastError());
	}

	return STATUS_SUCCESS;
}