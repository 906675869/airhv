#pragma warning( disable : 4201 4244)
#include <ntifs.h>
#include "hypervisor_gateway.h"
#include "log.h"
#include "hookfunction.h"

HookGlobalData hgData;

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


VOID HookedKeStackAttachProcess(
	_Inout_ PRKPROCESS PROCESS,
	_Out_ PRKAPC_STATE ApcState
);

void HookedMemmove(_Out_writes_bytes_all_opt_(_Size) void* _Dst, _In_reads_bytes_opt_(_Size) const void* _Src, _In_ size_t _Size);
// void* NtCreateFileAddress;

NTSTATUS HookedMmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
VOID
(*OriginalKeStackAttachProcess)(
	_Inout_ PRKPROCESS PROCESS,
	_Out_ PRKAPC_STATE ApcState
	);

NTSTATUS(*OriginalMmCopyVirtualMemory)(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

NTSTATUS(*OriginalNtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength
	);

NTSTATUS(*OriginalNtOpenProcess)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
	);

BOOLEAN(*OriginalMmIsAddressValid)(
	_In_ PVOID VirtualAddress
	);

void (*OriginalMemmove)(_Out_writes_bytes_all_opt_(_Size) void* _Dst, _In_reads_bytes_opt_(_Size) const void* _Src, _In_ size_t _Size);



HookStruct hsarr[] = {
	{L"NtCreateFile", HookedNtCreateFile, (void**)&OriginalNtCreateFile },
	{ L"NtOpenProcess", HookedNtOpenProcess, (void**)&OriginalNtOpenProcess},
	{ L"MmIsAddressValid", HookedMmIsAddressValid, (void**)&OriginalMmIsAddressValid },
	{ L"MmCopyVirtualMemory", HookedMmCopyVirtualMemory, (void**)&OriginalMmCopyVirtualMemory },
	// { L"KeStackAttachProcess", HookedKeStackAttachProcess, (void**)&OriginalKeStackAttachProcess },
	// { L"RtlCopyMemory", HookedMemmove, (void**)&OriginalMemmove }


};

void HookedMemmove(_Out_writes_bytes_all_opt_(_Size) void* _Dst, _In_reads_bytes_opt_(_Size) const void* _Src, _In_ size_t _Size) {
	LogInfo("HookedMemmove dst=%xll src=%xll size=%xll", _Dst, _Src, _Size);
	OriginalMemmove(_Dst, _Src, _Size);
}


VOID HookedKeStackAttachProcess(
	_Inout_ PRKPROCESS PROCESS,
	_Out_ PRKAPC_STATE ApcState
) {
	// 目标进程是保护的进程，伪装
	if (hgData.pid != 0 && hgData.pid != 4 && (int)PsGetProcessId(PROCESS) == hgData.pid) {
		PEPROCESS eproc = NULL;
		PsLookupProcessByProcessId((HANDLE)4, &eproc);
		OriginalKeStackAttachProcess(eproc, ApcState);
		return;
	}
	OriginalKeStackAttachProcess(PROCESS, ApcState);

	//MmCopyVirtualMemory(0, 0, );
	// NtReadVirtualMemory(0,0,0,0);
	
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
	auto pid = PsGetProcessId(SourceProcess);
	if ((int)pid == hgData.pid) {
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
		if ((int)PsGetCurrentProcessId() == hgData.pid 
			&& VirtualAddress >= hgData.userModelRegionStart
			&& VirtualAddress <= hgData.userModelRegionEnd) {
			return false;
		}
	}
	return OriginalMmIsAddressValid(VirtualAddress);
}