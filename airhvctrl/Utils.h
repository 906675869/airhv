#pragma once
#include <ntifs.h>
#include "NtStruct.h"


typedef struct _NTAPI_OFFSETS
{
	ULONG SeAuditProcessCreationInfoOffset;
	ULONG BypassProcessFreezeFlagOffset;
	ULONG ThreadHideFromDebuggerFlagOffset;
	ULONG ThreadBreakOnTerminationFlagOffset;
	ULONG PicoContextOffset;
	ULONG RestrictSetThreadContextOffset;
}NTAPI_OFFSETS;

template <typename T>
PEPROCESS PidToProcess(T Pid)
{
	PEPROCESS Process;
	PsLookupProcessByProcessId((HANDLE)Pid, &Process);
	return Process;
}



PEPROCESS GetProcessByName(CONST WCHAR* ProcessName);

