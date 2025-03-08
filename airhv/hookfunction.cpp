#pragma warning( disable : 4201 4244)
#include <ntifs.h>
#include "hypervisor_gateway.h"
#include "log.h"
#include "hookfunction.h"

HookGlobalData hgData;

OriginalMmCopyVirtualMemoryType OriginalMmCopyVirtualMemory;
OriginalNtCreateFileType OriginalNtCreateFile;
OriginalNtOpenProcessType OriginalNtOpenProcess;
OriginalMmIsAddressValidType OriginalMmIsAddressValid;
OriginalMemmoveType OriginalMemmove;
OriginalProbeForReadType OriginalProbeForRead;
OriginalNtDeviceIoControlFileType OriginalNtDeviceIoControlFile;


NTSTATUS NTAPI HookedNtCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
);

NTSTATUS HookedNtOpenProcess(OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId);


void HookedMemmove(_Out_writes_bytes_all_opt_(_Size) void* _Dst, _In_reads_bytes_opt_(_Size) const void* _Src, _In_ size_t _Size);

NTSTATUS HookedMmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

VOID HookedProbeForRead(
	volatile VOID* Address,
	_In_ SIZE_T Length,
	_In_ ULONG Alignment
);


NTSTATUS
HookedNtDeviceIoControlFile(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG IoControlCode,
	PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength
);


HookStruct hsarr[] = {
	{ L"NtCreateFile", HookedNtCreateFile, (void**)&OriginalNtCreateFile },
	{ L"NtOpenProcess", HookedNtOpenProcess, (void**)&OriginalNtOpenProcess},
	{ L"MmIsAddressValid", HookedMmIsAddressValid, (void**)&OriginalMmIsAddressValid },
	{ L"MmCopyVirtualMemory", HookedMmCopyVirtualMemory, (void**)&OriginalMmCopyVirtualMemory },
	{ L"ProbeForRead", HookedProbeForRead, (void**)&OriginalProbeForRead },
	// { L"NtDeviceIoControlFile", HookedNtDeviceIoControlFile, (void**)&OriginalNtDeviceIoControlFile },
	// { L"RtlCopyMemory", HookedMemmove, (void**)&OriginalMemmove }


};

void HookedMemmove(_Out_writes_bytes_all_opt_(_Size) void* _Dst, _In_reads_bytes_opt_(_Size) const void* _Src, _In_ size_t _Size) {
	LogInfo("HookedMemmove dst=%xll src=%xll size=%xll", _Dst, _Src, _Size);
	OriginalMemmove(_Dst, _Src, _Size);
}

NTSTATUS
HookedNtDeviceIoControlFile(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG IoControlCode,
	PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength
) {
	/*NTSTATUS status;
	POBJECT_NAME_INFORMATION pNameInfo;
	ULONG returnLength;
	status = ObQueryNameString(FileHandle, NULL, 0, &returnLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		pNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(PagedPool, returnLength, 'Tag');
		if (pNameInfo) {
			status = ObQueryNameString(FileHandle, pNameInfo, returnLength, &returnLength);
			if (NT_SUCCESS(status)) {
				LogInfo("Object Name: %wZ\n", &pNameInfo->Name);
			}
			ExFreePool(pNameInfo);
		}
	}*/
	LogInfo("IoControlCode is: %d", IoControlCode);


	return OriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode ,InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);



}





void HookAllNtFunction() {
	LogInfo("Start HookAllFunction~");
	// 隐藏
	hvgt::hypervisor_visible(false);

	for (const auto& hs : hsarr) {
		UNICODE_STRING routine_name;
		RtlInitUnicodeString(&routine_name, hs.SourceString);
		PVOID originalFunctionAddr = MmGetSystemRoutineAddress(&routine_name);
		if (!originalFunctionAddr) {
			LogError("MmGetSystemRoutineAddress Get Address Fail %wZ", routine_name);
			break;
		}
		if (!hvgt::hook_function(originalFunctionAddr, hs.hookFunction, hs.originFunction)) {
			LogError("Couldn't hook %wZ", routine_name);
			break;
		}
		else {
			LogInfo("Hook Function Success %wZ", routine_name);
		}
	}
	LogInfo("HookAllFunction Success!");
}


NTSTATUS HookedMmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize)
{
	if (hgData.pid == 0) {
		return OriginalMmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, BufferSize, PreviousMode, ReturnSize);
	}
	ULONG pid = (ULONG)PsGetProcessId(SourceProcess);
	if (pid == hgData.pid) {
		return STATUS_SUCCESS;
	}
	ULONG targetPid = (ULONG)PsGetProcessId(TargetProcess);
	if (targetPid == hgData.pid) {
		return STATUS_SUCCESS;
	}
	return OriginalMmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, BufferSize, PreviousMode, ReturnSize);
}


NTSTATUS HookedNtOpenProcess(OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId) {
	// 无保护状态
	if (hgData.pid == 0) {
		return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}
	auto PreMode = ExGetPreviousMode();
	if (PreMode != KernelMode){
		__try
		{
			ProbeForRead(ClientId, sizeof(CLIENT_ID), sizeof(ULONG));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}
	if (ClientId != NULL){
		auto PID = (ULONG)ClientId->UniqueProcess;
		if (hgData.pid == PID) {
			LogError("NtOpenProcess DENIED...%d", PID);
			return STATUS_ACCESS_DENIED;
		}
	}
	return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}


NTSTATUS NTAPI HookedNtCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
)
{
	if (hgData.fileName == L"") {
		return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}
	__try
	{
		ProbeForRead(FileHandle, sizeof(HANDLE), 1);
		ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
		ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
		ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
		if (wcsstr(ObjectAttributes->ObjectName->Buffer, hgData.fileName) != NULL)
		{
			return STATUS_INVALID_BUFFER_SIZE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}



BOOLEAN HookedMmIsAddressValid(_In_ PVOID VirtualAddress) {
	// 内核层
	if (hgData.regionStart != 0 && hgData.regionEnd != 0 && hgData.regionStart != hgData.regionEnd) {
		// 在区间
		if (VirtualAddress >= hgData.regionStart && VirtualAddress <= hgData.regionEnd) {
			return false;
		}
	}
	// 用户层
	if (hgData.pid != 0 && hgData.userModelRegionStart != 0 && hgData.userModelRegionEnd != 0 
		&& hgData.userModelRegionStart != hgData.userModelRegionEnd) {
		if ((ULONG)PsGetCurrentProcessId() == hgData.pid 
			&& VirtualAddress >= hgData.userModelRegionStart
			&& VirtualAddress <= hgData.userModelRegionEnd) {
			return false;
		}
	}
	return OriginalMmIsAddressValid(VirtualAddress);
}

VOID HookedProbeForRead(
	volatile VOID* Address,
	_In_ SIZE_T Length,
	_In_ ULONG Alignment
) {
	// 是保护的地址，直接异常
	if (hgData.pid != 0 && hgData.userModelRegionStart != 0 && hgData.userModelRegionEnd != 0
		&& hgData.userModelRegionStart != hgData.userModelRegionEnd) {
		if ((ULONG)PsGetCurrentProcessId() == hgData.pid
			&& Address >= hgData.userModelRegionStart
			&& Address <= hgData.userModelRegionEnd) {
			ExRaiseDatatypeMisalignment();
		}
	}
	OriginalProbeForRead(Address, Length, Alignment);
}