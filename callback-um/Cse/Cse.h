#pragma once
/*
 Cse - Console function prefix
*/

NTSTATUS
CseCreate(
	VOID
);

NTSTATUS
CseTerminate(
	VOID
);

NTSTATUS
CseClear(
	VOID
);

NTSTATUS
CseOutputA(
	const char* Text
);

NTSTATUS
CseOutputW(
	const wchar_t* Text
);

NTSTATUS
CseWaitInput(
	VOID
);