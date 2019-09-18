#pragma once

#ifndef ALIGN_UP
/***/#define ALIGN_UP(x,n)		(((DWORD_PTR)(x) + (n - 1)) & ~(n - 1))
#endif

#ifndef ALIGN_DOWN
/***/#define ALIGN_DOWN(x,n)	(((DWORD_PTR)(x)) & ~(n - 1))
#endif

NTSTATUS InitAllocations();