#include "Utils.h"
#include "nt.h"

#define DRIVER_TAG 'DTG'

PEPROCESS GetProcessByName(CONST WCHAR* ProcessName)
{
	NTSTATUS Status;
	ULONG Bytes;

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, Bytes, DRIVER_TAG);
	if (ProcInfo == NULL)
		return NULL;

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
		return NULL;
	}

	UNICODE_STRING ProcessImageName;
	RtlCreateUnicodeString(&ProcessImageName, ProcessName);

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (Entry->ImageName.Buffer != NULL)
		{
			if (RtlCompareUnicodeString(&Entry->ImageName, &ProcessImageName, TRUE) == 0)
			{
				PEPROCESS CurrentPeprocess = PidToProcess(Entry->ProcessId);
				ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
				return CurrentPeprocess;
			}
		}
	}

	ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
	return NULL;
}
