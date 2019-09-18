#pragma once

typedef struct _SEMAPHORE
{
	volatile LONG_PTR BeingOwned;
}SEMAPHORE,*PSEMAPHORE;

static FORCEINLINE BOOLEAN TryLockSemaphore(const PSEMAPHORE Sema) {

#ifdef _M_AMD64
	return _InterlockedCompareExchange64(&Sema->BeingOwned, TRUE, FALSE) == FALSE;
#else
	return _InterlockedCompareExchange(&Sema->BeingOwned, TRUE, FALSE) == FALSE;
#endif
}

static FORCEINLINE VOID UnlockSemaphore(const PSEMAPHORE Sema) {

#ifdef _M_AMD64
	_InterlockedExchange64(&Sema->BeingOwned, FALSE);
#else
	_InterlockedExchange(&Sema->BeingOwned, FALSE);
#endif
}

static FORCEINLINE VOID LockSemaphore(const PSEMAPHORE Sema) {

	while (!TryLockSemaphore(Sema))
		_mm_pause();
}