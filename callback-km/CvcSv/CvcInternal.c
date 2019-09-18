#include "../Native/Native.h"
#include "../hde/hde64.h"
#include "../../Declaration.h"
#include "Cvc.h"
#include "CvcInternal.h"

MmCreateKernelStack_t MmCreateKernelStack = NULL;
MmDeleteKernelStack_t MmDeleteKernelStack = NULL;


#ifndef DXGK_WIN32K_QUERY_INTERFACE
/***/#define DXGK_WIN32K_QUERY_INTERFACE CTL_CODE(FILE_DEVICE_VIDEO,0x815,METHOD_NEITHER,FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

KiCallUserMode_t ShellKiCallUserMode = NULL;
PVOID* pfnShellUmDispatcher = NULL;

PDXGKWIN32K_INTERFACE gDxgkInterface = NULL;
ULONG OpenAdapterIdx = 0;
OpenAdapter_t pfOpenAdapter = NULL;

KPCR ** KiProcessorBlock = NULL;
ULONG OfTrapFrame = 0;
ULONG OfIdealProcessor = 0;
ULONG OfParentNode = 0;
ULONG OfNodeNumber = 0;

#pragma code_seg(push)
#pragma code_seg("INIT")

NTSTATUS
CvcipFindDxgkInterface(
	VOID
) {

	PAGED_CODE();
	PDXGKWIN32K_INTERFACE pInterface = NULL;
	PFILE_OBJECT gpDxgkFileObject = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS Csrss = NULL;
	KAPC_STATE Kapc;

	Status = UtFindProcesses(L"csrss.exe", &Csrss, NULL);

	if (!NT_SUCCESS(Status)) {

		goto OutStub;
	}

	KeStackAttachProcess(Csrss, &Kapc);

	pInterface = (PDXGKWIN32K_INTERFACE)ExAllocatePoolWithTag(NonPagedPool, sizeof(DXGKWIN32K_INTERFACE), MEMORY_TAG);

	if (!pInterface) {

		Status = STATUS_NO_MEMORY;
		goto OutStub;
	}

	RtlSecureZeroMemory(pInterface, sizeof(DXGKWIN32K_INTERFACE));

	PVOID win32k = NULL;
	Status = UtFindSystemImage("win32kbase.sys", &win32k);

	if (!NT_SUCCESS(Status)) {

		Status = UtFindSystemImage("win32k.sys", &win32k);
		if (!NT_SUCCESS(Status)) {

			DbgPrint("%s: UtFindSystemImage status 0x%X\n", __FUNCTION__, Status);
			Status = STATUS_MISSING_SYSTEMFILE;
			goto OutStub;
		}
	}

	PVOID SectionMin, SectionMax;
	if (!RtlSectionRange(win32k, ".data", &SectionMin, &SectionMax)) {

		DbgPrint("%s: RtlSectionRange failed\n",__FUNCTION__);
		Status = STATUS_UNSUCCESSFUL;
		goto OutStub;
	}

	UNICODE_STRING ObjectName = RTL_CONSTANT_STRING(L"\\Device\\DxgKrnl");
	PDEVICE_OBJECT gpDxgkDeviceObject = NULL;

	Status = IoGetDeviceObjectPointer(
		&ObjectName,
		GENERIC_READ | GENERIC_WRITE,
		&gpDxgkFileObject,
		&gpDxgkDeviceObject
	);

	if (!NT_SUCCESS(Status)) {

		goto OutStub;
	}

	IO_STATUS_BLOCK IoStatus;
	KEVENT Event;
	KeInitializeEvent(
		&Event,
		SynchronizationEvent,
		FALSE
	);

	Status = STATUS_UNSUCCESSFUL;

	for (WORD i = 1; i < 0xFF; i++) {//for windows 10

		pInterface->Magic = i;

		for (WORD j = 0x200; j < sizeof(DXGKWIN32K_INTERFACE); j += sizeof(DWORD64)) {

			pInterface->Size = j;

			RtlSecureZeroMemory(&IoStatus, sizeof(IoStatus));

			PIRP pIrp = IoBuildDeviceIoControlRequest(
				DXGK_WIN32K_QUERY_INTERFACE,
				gpDxgkDeviceObject,
				pInterface,
				pInterface->Size,
				pInterface,
				pInterface->Size,
				TRUE,
				&Event,
				&IoStatus
			);

			if (!pIrp) {

				Status = STATUS_NO_MEMORY;
				goto OutStub;
			}

			Status = IofCallDriver(gpDxgkDeviceObject, pIrp);

			if (Status == STATUS_PENDING) {

				KeWaitForSingleObject(
					&Event,
					Executive,
					KernelMode,
					FALSE,
					NULL
				);
				Status = IoStatus.Status;
			}

			if (NT_SUCCESS(Status)) {

				break;
			}
		}
		if (NT_SUCCESS(Status)) {

			break;
		}
	}

	if (!NT_SUCCESS(Status)) {

		DbgPrint("%s: Can't query dxgk interface 0x%X\n", __FUNCTION__, Status);
		Status = STATUS_UNSUCCESSFUL;
		goto OutStub;
	}

	ULONG IdxOpenAdapter = (ULONG)-1;

	__try {

		for (ULONG i = 0x3; i < 0x10; i++) {

			DWORD64 Temp = (DWORD64)pInterface->pFn[i];
			hde64s hde;

			do {

				hde64_disasm((PVOID)Temp, &hde);


				if (hde.opcode == 0x0F && (hde.opcode2 >= 0x80 && hde.opcode2 <= 0x8F)) {

					DWORD64 Temp1 = Temp + hde.len + (int)hde.imm.imm32;
					hde64s hde1;

					do {

						hde64_disasm((PVOID)Temp1, &hde1);

						if (hde1.imm.imm64 == 0x7D1) {

							IdxOpenAdapter = i;
							break;
						}

						Temp1 += hde1.len;

					} while (
						hde1.opcode != 0xC3 &&
						hde1.opcode != 0xC2 &&
						hde1.opcode != 0xCC &&
						hde1.opcode != 0xE9
						);
				}

				if (hde.imm.imm64 == 0x7D1) {

					IdxOpenAdapter = i;
					break;
				}
				else if (IdxOpenAdapter != (ULONG)-1) {

					break;
				}

				Temp += hde.len;

			} while (
				hde.opcode != 0xC3 &&
				hde.opcode != 0xC2 &&
				hde.opcode != 0xCC 
				);

			if (IdxOpenAdapter != (ULONG)-1) {

				break;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		DbgPrint("%s: IdxOpenAdapter Exception\n", __FUNCTION__);
		Status = GetExceptionCode();
	}

	if (!NT_SUCCESS(Status)) {

		goto OutStub;
	}

	if (IdxOpenAdapter != (ULONG)-1) {

		OpenAdapterIdx = IdxOpenAdapter;
	}
	else {

		DbgPrint("%s: IdxOpenAdapter == -1\n", __FUNCTION__);
		Status = STATUS_UNSUCCESSFUL;
		goto OutStub;
	}

	PDXGKWIN32K_INTERFACE pDxInterface = NULL;
	PBYTE ScanPtr = (PBYTE)SectionMin;

	__try {

		while (ScanPtr < (PBYTE)SectionMax - 0x30) {

			if (RtlEqualMemory(ScanPtr, pInterface->pFn, 0x30)) {

				pDxInterface = (PDXGKWIN32K_INTERFACE)(ScanPtr - FIELD_OFFSET(DXGKWIN32K_INTERFACE, pFn));
				break;
			}

			ScanPtr++;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		DbgPrint("%s: pDxInterface Exception\n", __FUNCTION__);
		Status = STATUS_UNSUCCESSFUL;
	}

	if (!NT_SUCCESS(Status)) {

		goto OutStub;
	}

	if (pDxInterface != NULL) {

		gDxgkInterface = pDxInterface;
	}
	else {

		pDxInterface = LdrFindProcAdressA(win32k, "?gDxgkInterface@@3U_DXGKWIN32K_INTERFACE@@A");

		if (!pDxInterface) {

			DbgPrint("%s: pDxInterface == NULL\n", __FUNCTION__);
			Status = STATUS_UNSUCCESSFUL;
			goto OutStub;
		}
	}

	pfOpenAdapter = (OpenAdapter_t)gDxgkInterface->pFn[OpenAdapterIdx];

OutStub:;

	if (Csrss) {

		KeUnstackDetachProcess(&Kapc);
		ObDereferenceObject(Csrss);
	}

	if (gpDxgkFileObject) {

		ObDereferenceObject(gpDxgkFileObject);
	}

	if (pInterface) {

		ExFreePoolWithTag(pInterface, MEMORY_TAG);
	}

	return Status;
}

NTSTATUS
CvcipSolveTrapFrameOffset(
	VOID
) {

	PAGED_CODE();
	UNICODE_STRING ExpName = RTL_CONSTANT_STRING(L"KeRaiseUserException");
	DWORD64 Temp = (DWORD64)MmGetSystemRoutineAddress(&ExpName);

	if (!Temp) {

		return STATUS_NOT_IMPLEMENTED;
	}

	hde64s hde;

	uint8_t ThreadModRM = (uint8_t)-1;
	uint8_t ThreadRexR = (uint8_t)-1;

	do {

		hde64_disasm((PVOID)Temp, &hde);

		if (ThreadModRM == (uint8_t)-1) {

			if (hde.p_seg == PREFIX_SEGMENT_GS &&
				hde.disp.disp32 == 0x188 &&
				(hde.flags & F_MODRM)
				) {

				ThreadModRM = hde.modrm_reg;
				ThreadRexR = hde.rex_r;
			}
		}
		else if ((hde.flags & F_MODRM) && (hde.modrm & 0x7) == ThreadModRM) {

			if (!ThreadRexR &&hde.rex_w) {

				OfTrapFrame = hde.disp.disp32;
				break;
			}
			else if (ThreadRexR && hde.rex_b) {

				OfTrapFrame = hde.disp.disp32;
				break;
			}
		}

		Temp += hde.len;

	} while (
		hde.opcode != 0xC3 &&
		hde.opcode != 0xC2 &&
		hde.opcode != 0xCC
		);



	return OfTrapFrame ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


typedef struct _RelAsm {
	ULONG UniqueID;
	ULONG SrcRel;
	DWORD64 DstAbs;
}RelAsm;

typedef struct _LdrShell {

	RelAsm	RelCalls[0x10];
	int		RelCallCount;

	RelAsm	RelData[0x10];
	int		RelDataCount;

	RelAsm	RelJumpsOut[0x10];
	int		RelJumpOutCount;

}LdrShell, *pLdrShell;

int
RtlUniqueRef(
	RelAsm* Data,
	int DataLen
) {

	ULONG Out = 0;

	for (int i = 0; i < DataLen; i++) {

		BOOLEAN Unique = TRUE;
		int j = i - 1;

		while (j >= 0) {

			if (Data[j].DstAbs == Data[i].DstAbs) {

				Unique = FALSE;
				Data[i].UniqueID = Data[j].UniqueID;
				break;
			}
			j--;
		}

		if (Unique) {

			Out++;
			Data[i].UniqueID = Out;
		}
	}

	return Out;
}

NTSTATUS
CvcipBuildUsermodeCallShell(
	const DWORD64 KiCallUserMode
) {

	const pLdrShell pLdr = (pLdrShell)ExAllocatePoolWithTag(
		NonPagedPool,
		sizeof(LdrShell),
		MEMORY_TAG
	);

	if (!pLdr) {

		return STATUS_NO_MEMORY;
	}

	RtlZeroMemory(pLdr, sizeof(LdrShell));

	DWORD64 KeUserCallbackDispatcher = 0;
	DWORD64 KiSystemServiceExit = 0;

	hde64s hde;
	DWORD64 Temp = KiCallUserMode;

	do {

		hde64_disasm((PVOID)Temp, &hde);
		Temp += hde.len;
	} while (
		hde.opcode != 0xC3 &&
		hde.opcode != 0xC2 &&
		hde.opcode != 0xCC
		);

	const DWORD64 KiCallUserModeEnd = Temp;
	const DWORD64 FunctionLen = KiCallUserModeEnd - KiCallUserMode;

	Temp = KiCallUserMode;

	do {

		hde64_disasm((PVOID)Temp, &hde);

		if (hde.opcode == 0xE8) {

			pLdr->RelCalls[pLdr->RelCallCount].SrcRel = (ULONG)(Temp - KiCallUserMode);
			pLdr->RelCalls[pLdr->RelCallCount].DstAbs = Temp + hde.len + (int)hde.imm.imm32;

			pLdr->RelCallCount++;
		}
		else if (hde.modrm_rm == 0x5 && hde.modrm_mod == 0x0) {

			const DWORD64 Ptr = Temp + hde.len + (int)hde.disp.disp32;

			if (hde.opcode == 0x8B && (hde.flags & F_PREFIX_REX)) {

				KeUserCallbackDispatcher = Ptr;

			}
			else if (hde.opcode == 0x8D) {

				KiSystemServiceExit = Ptr;
			}

			pLdr->RelData[pLdr->RelDataCount].SrcRel = (ULONG)(Temp - KiCallUserMode);
			pLdr->RelData[pLdr->RelDataCount].DstAbs = Ptr;
			pLdr->RelDataCount++;
		}
		else if (hde.opcode == 0x0F && (hde.opcode2 >= 0x80 && hde.opcode2 <= 0x8F)) {

			const DWORD64 Ptr = Temp + hde.len + (int)hde.imm.imm32;

			if (!(Ptr > KiCallUserMode && Ptr < KiCallUserModeEnd)) {

				pLdr->RelJumpsOut[pLdr->RelJumpOutCount].SrcRel = (ULONG)(Temp - KiCallUserMode);
				pLdr->RelJumpsOut[pLdr->RelJumpOutCount].DstAbs = Ptr;
				pLdr->RelJumpOutCount++;
			}
		}
		if (pLdr->RelJumpOutCount >= 0x10 || pLdr->RelDataCount >= 0x10 || pLdr->RelCallCount >= 0x10) {

			break;
		}

		Temp += hde.len;
	} while (
		hde.opcode != 0xC3 &&
		hde.opcode != 0xC2 &&
		hde.opcode != 0xCC
		);

	if (pLdr->RelJumpOutCount >= 0x10 || pLdr->RelDataCount >= 0x10 || pLdr->RelCallCount >= 0x10) {

		DbgPrint("%s: Relative data >= 0x10, extend size\n", __FUNCTION__);
		return STATUS_UNSUCCESSFUL;
	}

	const BYTE CallRel[] = { 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00 };
	const BYTE JumpRel[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	const BYTE LogicJumpRel[] = { 0x00, 0x00 };
	const BYTE AbsJump[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, };

	const int UniqueData = RtlUniqueRef(pLdr->RelData, pLdr->RelDataCount);
	const int UniqueCalls = RtlUniqueRef(pLdr->RelCalls, pLdr->RelCallCount);

	const DWORD64 CallStubLen = ALIGN_UP_BY(
		ALIGN_UP_BY(
			sizeof(CallRel) +
			sizeof(JumpRel),
			MEMORY_ALLOCATION_ALIGNMENT) + sizeof(DWORD64),
		MEMORY_ALLOCATION_ALIGNMENT);

	const DWORD64 JumpStubLen = ALIGN_UP_BY(
		ALIGN_UP_BY(
			sizeof(LogicJumpRel) +
			sizeof(JumpRel) +
			sizeof(AbsJump),
			MEMORY_ALLOCATION_ALIGNMENT) + sizeof(DWORD64),
		MEMORY_ALLOCATION_ALIGNMENT);

	const DWORD64 TotalLen =
		FunctionLen +
		MEMORY_ALLOCATION_ALIGNMENT +
		UniqueData * sizeof(DWORD64) +
		UniqueCalls * CallStubLen +
		pLdr->RelJumpOutCount * JumpStubLen;

	DbgPrint("%s: TotalLen = 0x%X\n", __FUNCTION__, TotalLen);

	const DWORD64 ShellPtr = (DWORD64)ExAllocatePoolWithTag(
		NonPagedPoolExecute,
		TotalLen,
		MEMORY_TAG
	);

	if (!ShellPtr) {

		ExFreePoolWithTag(pLdr, MEMORY_TAG);
		return STATUS_NO_MEMORY;
	}

	RtlSecureZeroMemory(
		(PVOID)ShellPtr,
		TotalLen
	);

	RtlCopyMemory((PVOID)ShellPtr, (PVOID)KiCallUserMode, FunctionLen);

	PVOID* DataPtr = (PVOID*)ALIGN_UP_BY(ShellPtr + FunctionLen, MEMORY_ALLOCATION_ALIGNMENT);

	/*
	relocate all data refs
	*/

	for (int i = 0; i < pLdr->RelDataCount; i++) {

		const DWORD64 TargetInstruction = ShellPtr + pLdr->RelData[i].SrcRel;

		hde64_disasm((PVOID)TargetInstruction, &hde);

		if (hde.opcode == 0xF6) {//test

			*(int*)(TargetInstruction + 0x2) = (int)((DWORD64)&DataPtr[pLdr->RelData[i].UniqueID - 1] - (TargetInstruction + 0x7));

		}
		else if (hde.opcode == 0x8D) {//lea KiSystemServiceExit

			*(char*)(TargetInstruction + 0x1) = 0x8B;//replace to mov
			*(int*)(TargetInstruction + 0x3) = (int)((DWORD64)&DataPtr[pLdr->RelData[i].UniqueID - 1] - (TargetInstruction + 0x7));
		}
		else {//mov

			if (hde.flags & F_PREFIX_REX) {

				*(int*)(TargetInstruction + 0x3) = (int)((DWORD64)&DataPtr[pLdr->RelData[i].UniqueID - 1] - (TargetInstruction + 0x7));
			}
			else {

				*(int*)(TargetInstruction + 0x2) = (int)((DWORD64)&DataPtr[pLdr->RelData[i].UniqueID - 1] - (TargetInstruction + 0x6));
			}
		}

		if (hde.opcode != 0x8D) {

			*(DWORD64*)&DataPtr[pLdr->RelData[i].UniqueID - 1] = *(DWORD64*)pLdr->RelData[i].DstAbs;

			if (pLdr->RelData[i].DstAbs == KeUserCallbackDispatcher) {

				pfnShellUmDispatcher = &DataPtr[pLdr->RelData[i].UniqueID - 1];
			}
		}
		else {

			*(DWORD64*)&DataPtr[pLdr->RelData[i].UniqueID - 1] = pLdr->RelData[i].DstAbs;
		}

	}


	const DWORD64 CallStubsPtr = ALIGN_UP_BY((DWORD64)&DataPtr[UniqueData], MEMORY_ALLOCATION_ALIGNMENT);

	/*
	call original -> jmp callstub
	...
	callstub:
	call [calle pointer]
	jmp back
	...
	dq calle pointer
	*/

	for (int i = 0; i < pLdr->RelCallCount; i++) {

		const DWORD64 StubPtr = CallStubsPtr + CallStubLen * (pLdr->RelCalls[i].UniqueID - 1);
		const DWORD64 TargetJump = ShellPtr + pLdr->RelCalls[i].SrcRel;
		const DWORD64 TargetJumpRet = TargetJump + sizeof(JumpRel);

		/*
		set rva jump to stub
		*/

		RtlCopyMemory((PVOID)TargetJump, JumpRel, sizeof(JumpRel));

		*(int*)(TargetJump + 0x1) = (int)(StubPtr - TargetJumpRet);

		/*
		call function by pointer at rva
		*/

		RtlCopyMemory((PVOID)StubPtr, CallRel, sizeof(CallRel));

		*(int*)(StubPtr + 0x2) = (int)(ALIGN_UP_BY(StubPtr + sizeof(CallRel) + sizeof(JumpRel), MEMORY_ALLOCATION_ALIGNMENT) - (StubPtr + sizeof(CallRel)));

		/*
		set absolute pointer for call
		*/

		*(DWORD64*)ALIGN_UP_BY(StubPtr + sizeof(CallRel) + sizeof(JumpRel), MEMORY_ALLOCATION_ALIGNMENT) = pLdr->RelCalls[i].DstAbs;

		RtlCopyMemory((PVOID)(StubPtr + sizeof(CallRel)), JumpRel, sizeof(JumpRel));

		/*
		jumps back to code
		*/

		*(int*)(StubPtr + sizeof(CallRel) + 0x1) = (int)(TargetJumpRet - (StubPtr + sizeof(CallRel) + sizeof(JumpRel)));
	}

	const DWORD64 RelJumpsOutPtr = ALIGN_UP_BY(CallStubsPtr + CallStubLen * (UniqueCalls - 1), MEMORY_ALLOCATION_ALIGNMENT);

	/*
	j* out original -> jmp jmpstub
	...
	jmpstub:
	j* rel8 pass
	jmp back
	pass:
	jmp qword ptr [jump pointer]
	...
	dq jump pointer
	*/

	for (int i = 0; i < pLdr->RelJumpOutCount; i++) {

		const DWORD64 StubPtr = RelJumpsOutPtr + JumpStubLen * i;
		const DWORD64 TargetJump = ShellPtr + pLdr->RelJumpsOut[i].SrcRel;
		const DWORD64 TargetJumpRet = TargetJump + sizeof(JumpRel);

		RtlCopyMemory((PVOID)StubPtr, LogicJumpRel, sizeof(LogicJumpRel));

		/*
		set opcode for rel8 logical jump form rel32 src
		*/

		*(char*)StubPtr = *(char*)(TargetJump + 0x1) - 0x10;

		/*
		set rel8 for logical jump to pass mark
		*/

		*(char*)(StubPtr + 0x1) = sizeof(JumpRel);

		/*
		write jump back if not pass
		*/

		RtlCopyMemory((PVOID)(StubPtr + sizeof(LogicJumpRel)), JumpRel, sizeof(JumpRel));

		/*
		set rel32 for jump back
		*/

		*(int*)(StubPtr + sizeof(LogicJumpRel) + 0x1) = (int)(TargetJumpRet - (StubPtr + sizeof(LogicJumpRel) + 0x5));


		RtlCopyMemory((PVOID)(StubPtr + sizeof(LogicJumpRel) + sizeof(JumpRel)), AbsJump, sizeof(AbsJump));

		/*
		set abs jump to pass address
		*/

		*(int*)(StubPtr + sizeof(LogicJumpRel) + sizeof(JumpRel) + 0x2) = (int)(
			(int)ALIGN_UP_BY(StubPtr + sizeof(LogicJumpRel) + sizeof(JumpRel) + sizeof(AbsJump), MEMORY_ALLOCATION_ALIGNMENT) -
			(StubPtr + sizeof(LogicJumpRel) + sizeof(JumpRel) + sizeof(AbsJump))
			);

		*(DWORD64*)ALIGN_UP_BY(StubPtr + sizeof(LogicJumpRel) + sizeof(JumpRel) + sizeof(AbsJump), MEMORY_ALLOCATION_ALIGNMENT) = pLdr->RelJumpsOut[i].DstAbs;

		/*
		set rva jump to stub
		*/

		RtlCopyMemory((PVOID)TargetJump, JumpRel, sizeof(JumpRel));

		*(int*)(TargetJump + 0x1) = (int)(StubPtr - TargetJumpRet);

		*(char*)(TargetJump + 0x5) = 0x90;//nop spare
	}


	ExFreePoolWithTag(pLdr, MEMORY_TAG);
	DbgPrint("%s: ShellPtr 0x%p\n", __FUNCTION__, ShellPtr);

	ShellKiCallUserMode = (KiCallUserMode_t)ShellPtr;

	return STATUS_SUCCESS;
}


NTSTATUS
CvcipSolveAllocatePagesForMdl(
	VOID
) {

	hde64s hde;

	DWORD64 Temp = (DWORD64)MmAllocatePagesForMdl;

	uint8_t ThreadModRMReg = (uint8_t)-1;
	uint8_t IdealProcModRMReg = (uint8_t)-1;
	uint8_t KiProcessorBlockModRMReg = (uint8_t)-1;
	uint8_t KiProcessorBlockRexR = (uint8_t)-1;
	uint8_t KPCRBModRMReg = (uint8_t)-1;
	uint8_t ParentNodeModRMReg = (uint8_t)-1;
	uint8_t NodeNumberModRMReg = (uint8_t)-1;


	do {

		hde64_disasm((PVOID)Temp, &hde);

		if (!OfIdealProcessor) {

			if (ThreadModRMReg == (uint8_t)-1) {

				if (hde.p_seg == PREFIX_SEGMENT_GS &&
					hde.disp.disp32 == 0x188 &&
					(hde.flags & F_MODRM)
					) {

					ThreadModRMReg = hde.modrm_reg;
				}
			}
			else if ((hde.flags & F_MODRM) && !(hde.flags & F_PREFIX_REX) && (hde.modrm & 0x7) == ThreadModRMReg) {

				OfIdealProcessor = hde.disp.disp32;
				IdealProcModRMReg = hde.modrm_reg;
			}
		}
		if (!KiProcessorBlock) {

			if (hde.modrm_rm == 0x5 && hde.modrm_mod == 0x0) {

				KiProcessorBlock = (KPCR **)(Temp + hde.len + (int)hde.disp.disp32);
				KiProcessorBlockModRMReg = hde.modrm_reg;
				KiProcessorBlockRexR = hde.rex_r;
			}
		}
		else if (KPCRBModRMReg == (uint8_t)-1) {

			if (hde.sib_base == KiProcessorBlockModRMReg && hde.sib_index == IdealProcModRMReg && hde.sib_scale == 0x3) {

				KPCRBModRMReg = hde.modrm_reg;
			}
		}
		else if (ParentNodeModRMReg == (uint8_t)-1) {

			if ((hde.modrm & 0x7) == KPCRBModRMReg) {

				OfParentNode = hde.disp.disp32;
				ParentNodeModRMReg = hde.modrm_reg;
			}
		}
		else if (NodeNumberModRMReg == (uint8_t)-1) {

			if ((hde.modrm & 0x7) == ParentNodeModRMReg) {

				OfNodeNumber = hde.disp.disp32;
				break;
			}
		}

		Temp += hde.len;

	} while (
		hde.opcode != 0xC3 &&
		hde.opcode != 0xC2 &&
		hde.opcode != 0xCC
		);

	return KiProcessorBlock && OfIdealProcessor && OfParentNode && OfNodeNumber ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


NTSTATUS
CvcipSolveKeUsermodeCallback(
	VOID
) {

	PAGED_CODE();

	UNICODE_STRING ExpName = RTL_CONSTANT_STRING(L"KeUserModeCallback");
	DWORD64 Temp = (DWORD64)MmGetSystemRoutineAddress(&ExpName);

	BOOLEAN ExpectMmCreateKernelStack = FALSE;
	BOOLEAN ExpectMmDeleteKernelStack = FALSE;

	DWORD64 KiCallUserMode = 0;
	if (!Temp) {

		return STATUS_NOT_IMPLEMENTED;
	}

	hde64s hde;

	do {

		hde64_disasm((PVOID)Temp, &hde);

		if (hde.opcode == 0xE8) {

			const DWORD64 Ptr = Temp + hde.len + (int)hde.imm.imm32;

			if (*(DWORD64*)Ptr == 0x4800000138EC8148) {// bytes of sub rsp, 138h + rex prefix of next instruction

				KiCallUserMode = Ptr;
			}
			else if (ExpectMmCreateKernelStack) {

				MmCreateKernelStack = (MmCreateKernelStack_t)Ptr;
				ExpectMmCreateKernelStack = FALSE;
			}
			else if (ExpectMmDeleteKernelStack) {

				MmDeleteKernelStack = (MmDeleteKernelStack_t)Ptr;
				ExpectMmDeleteKernelStack = FALSE;
			}
		}
		else if (hde.opcode == 0x33) {

			if (hde.modrm == 0xC9) {//xor ecx, ecx

				ExpectMmCreateKernelStack = TRUE;
			}
			else if (hde.modrm == 0xD2) {// xor edx, edx

				ExpectMmDeleteKernelStack = TRUE;
			}
		}

		Temp += hde.len;

	} while (
		hde.opcode != 0xC3 &&
		hde.opcode != 0xC2 &&
		hde.opcode != 0xCC
		);

	if (!KiCallUserMode) {

		DbgPrint("%s: !KiCallUserMode\n", __FUNCTION__);
		return STATUS_UNSUCCESSFUL;
	}

	if (MmCreateKernelStack && MmDeleteKernelStack) {

		if (!NT_SUCCESS(CvcipSolveAllocatePagesForMdl())) {

			DbgPrint("%s: !CvcipSolveAllocatePagesForMdl\n", __FUNCTION__);
			return STATUS_UNSUCCESSFUL;
		}
	}
	else if (MmCreateKernelStack || MmDeleteKernelStack) {

		DbgPrint("%s: MmCreateKernelStack || MmDeleteKernelStack\n", __FUNCTION__);
		return STATUS_UNSUCCESSFUL;
	}

	return CvcipBuildUsermodeCallShell(KiCallUserMode);
}

NTSTATUS
CvcInitInternals(
	VOID
) {

	PAGED_CODE();

	NTSTATUS Status = CvcipSolveTrapFrameOffset();

	if (!NT_SUCCESS(Status)) {

		DbgPrint("%s: Failed CvcipSolveTrapFrameOffset\n", __FUNCTION__);
		return Status;
	}

	Status = CvcipSolveKeUsermodeCallback();

	if (!NT_SUCCESS(Status)) {

		CvciExit();

		DbgPrint("%s: CvcipSolveKeUsermodeCallback\n",__FUNCTION__);

		return Status;
	}

	Status = CvcipFindDxgkInterface();

	if (!NT_SUCCESS(Status)) {

		CvciExit();

		DbgPrint("%s: CvcipFindDxgkInterface\n", __FUNCTION__);
		return Status;
	}

	return Status;
}

#pragma code_seg(pop)


#pragma code_seg(push)
#pragma code_seg("PAGE")

VOID
CvciHookOpenAdapter(
	PVOID pFn
) {

	gDxgkInterface->pFn[OpenAdapterIdx] = pFn;
}


VOID
CvciUnhookOpenAdapter(
	VOID
) {

	gDxgkInterface->pFn[OpenAdapterIdx] = (PVOID)pfOpenAdapter;
}

VOID
CvciExit(
	VOID
) {

	if (ShellKiCallUserMode) {

		ExFreePoolWithTag((PVOID)ShellKiCallUserMode, MEMORY_TAG);
	}
}

PVOID
CvciGetUserArgument(
	VOID
) {

	const _PKTRAP_FRAME Trap = *(_PKTRAP_FRAME*)((DWORD64)KeGetCurrentThread() + OfTrapFrame);
	return *(PVOID*)(Trap->Rbp + 0x8);
}

/*
Irql must be PASSIVE_LEVEL
All apc must be enabled
*/
NTSTATUS
CvciUsermodeCallout(
	CvcMsgTypeKe	MsgType,
	PVOID			pConnection,
	PVOID			Dispatcher,
	PVOID			InputBuffer,
	ULONG			InputLength,
	PVOID *			OutputBuffer,
	ULONG *			OutputLength
) {

	PAGED_CODE();
	NTSTATUS Status = STATUS_SUCCESS;

	*pfnShellUmDispatcher = Dispatcher;

	const _PKTRAP_FRAME Trap = *(_PKTRAP_FRAME*)((DWORD64)KeGetCurrentThread() + OfTrapFrame);
	ULONGLONG OldStack = Trap->Rsp;
	PCALLOUT_FRAME CalloutFrame = NULL;
	__try {

		ULONG Length = ALIGN_UP_BY(InputLength + sizeof(CALLOUT_FRAME), MEMORY_ALLOCATION_ALIGNMENT);

		CalloutFrame = (PCALLOUT_FRAME)(Trap->Rsp - Length);

		if (InputLength && InputBuffer) {

			RtlCopyMemory(CalloutFrame + 1, InputBuffer, InputLength);
		}
		
		CalloutFrame->MsgType = MsgType;
		CalloutFrame->Buffer = (PVOID)(CalloutFrame + 1);
		CalloutFrame->Length = InputLength;
		CalloutFrame->pConnection = pConnection;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = GetExceptionCode();
	}

	if (!NT_SUCCESS(Status)) {

		return Status;
	}

	//__debugbreak();

	Trap->Rsp = (ULONGLONG)CalloutFrame;

	if (MmCreateKernelStack && MmDeleteKernelStack) {//win 8+ version

		const ULONG IdealProcessor = *(ULONG*)((DWORD64)KeGetCurrentThread() + OfIdealProcessor);
		const DWORD64 ParentNode = *(DWORD64*)((DWORD64)KiProcessorBlock[IdealProcessor] + OfParentNode);
		const WORD NodeNumber = *(WORD*)(ParentNode + OfNodeNumber);

		DWORD64 StackBase = (DWORD64)MmCreateKernelStack(FALSE, NodeNumber, KeGetCurrentThread());

		if (StackBase) {

			PKSTACK_CONTROL KSC = (PKSTACK_CONTROL)(StackBase - sizeof(KSTACK_CONTROL));

			KSC->StackBase = StackBase;
			KSC->StackLimit = StackBase - KERNEL_STACK_SIZE;
			KSC->PreviousStackBase = *(DWORD64*)((DWORD64)KeGetCurrentThread() + 0x38);//KernelStack
			KSC->PreviousStackLimit = *(DWORD64*)((DWORD64)KeGetCurrentThread() + 0x30);//StackLimit
			KSC->PreviousInitialStack = *(DWORD64*)((DWORD64)KeGetCurrentThread() + 0x28);//InitialStack

			Status = ShellKiCallUserMode(
				OutputBuffer,
				OutputLength,
				KSC,
				StackBase
			);

			MmDeleteKernelStack((PVOID)StackBase, FALSE);
		}
		else {

			Status = STATUS_NO_MEMORY;
		}
	}
	else {//win 7 version

		Status = ShellKiCallUserMode(
			OutputBuffer,
			OutputLength,
			0,
			0
		);
	}
	Trap->Rsp = OldStack;

	return Status;
}
#pragma code_seg(pop)
