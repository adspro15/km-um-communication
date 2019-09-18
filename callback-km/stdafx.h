#pragma once
#include <ntifs.h>
#include <ntstatus.h>
#include <minwindef.h>
#include <ntimage.h>
#include <intrin.h>
#include "Nt.h"

#pragma intrinsic(_disable)
#pragma intrinsic(_enable)

#ifndef MEMORY_TAG
/***/#define MEMORY_TAG ' cvC'
#endif