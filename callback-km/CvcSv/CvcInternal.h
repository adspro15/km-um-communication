#pragma once

NTSTATUS
CvcInitInternals(
	VOID
);

VOID
CvciHookOpenAdapter(
	PVOID pFn
);

VOID
CvciUnhookOpenAdapter(
	VOID
);

VOID
CvciExit(
	VOID
);

PVOID
CvciGetUserArgument(
	VOID
);

typedef struct _CALLOUT_FRAME {
	CvcMsgTypeKe	MsgType;
	ULONG			Length;
	PVOID			Buffer;
	PVOID			pConnection;
} CALLOUT_FRAME, *PCALLOUT_FRAME;

NTSTATUS
CvciUsermodeCallout(
	CvcMsgTypeKe	MsgType,
	PVOID			pConnection,
	PVOID			Dispatcher,
	PVOID			InputBuffer,
	ULONG			InputLength,
	PVOID *			OutputBuffer,
	ULONG *			OutputLength
);
