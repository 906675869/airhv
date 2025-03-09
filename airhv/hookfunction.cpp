#pragma warning( disable : 4201 4244)
#include <ntifs.h>
#include "hypervisor_gateway.h"
#include "log.h"
#include "hookfunction.h"
#include <stdio.h>
#include "adf_io.h"

HookGlobalData hgData;

typedef UCHAR* (*PsGetProcessImageFileNameType)(PEPROCESS Process);

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
	{ L"NtDeviceIoControlFile", HookedNtDeviceIoControlFile, (void**)&OriginalNtDeviceIoControlFile },
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
	// Send 0x0001201F
	// UCHAR buffer[4];
	// IOCTL_AFD_SEND_DATAGRAM UDP 
	// IOCTL_AFD_SEND TCP
	if (IoControlCode != IOCTL_AFD_SEND && IoControlCode != IOCTL_AFD_SEND_DATAGRAM) {
		return OriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	}
	auto eps = PsGetCurrentProcess();
	UNICODE_STRING routine_name;
	RtlInitUnicodeString(&routine_name, L"PsGetProcessImageFileName");
	PVOID PsGetProcessImageFileNameAddr = MmGetSystemRoutineAddress(&routine_name);
	UCHAR* pName = {};
	if (PsGetProcessImageFileNameAddr) {
		PsGetProcessImageFileNameType _psGetProcessImageFileName = (PsGetProcessImageFileNameType)PsGetProcessImageFileNameAddr;
		pName = _psGetProcessImageFileName(eps);
	}
	ANSI_STRING  UP1, UP2, ProcessImageName;
	RtlInitAnsiString(&UP1, "DNF.exe");
	RtlInitAnsiString(&UP2, "SGuard64.exe");
	// 初始化进程镜像名称字符串
	RtlInitAnsiString(&ProcessImageName, (PCSZ)pName);
	if(!RtlEqualString(&ProcessImageName, &UP1, FALSE) && !RtlEqualString(&ProcessImageName, &UP2, FALSE)) {
		return OriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	}
	__try {
		ProbeForRead(InputBuffer, InputBufferLength, sizeof(UCHAR));

		AFD_SendRecvInfo* sendRecvInfo = (AFD_SendRecvInfo*)InputBuffer;
		AFD_Wsbuf* sbuf = (AFD_Wsbuf*)sendRecvInfo->BufferArray;
		PVOID _buf = sbuf->buf;

		#define MAX_PRINT_LENGTH 512

		// 在栈上分配缓冲区（适用于短数据）
		CHAR buffer[MAX_PRINT_LENGTH * 3 + 32];  // 每个字节最多占3字符（"%02X "）
		int offset = 0;
		// 遍历输入缓冲区
		ULONG printLength = min(sbuf->len, MAX_PRINT_LENGTH);
		for (int i = 0; i < printLength; i++) {
			UCHAR byte = ((UCHAR*)_buf)[i];
			offset += sprintf(buffer + offset, "%02X ", byte);
		}
		sprintf(buffer + offset, "\n");

		UNICODE_STRING routine_name;
		RtlInitUnicodeString(&routine_name, L"PsGetProcessImageFileName");
		PVOID originalFunctionAddr = MmGetSystemRoutineAddress(&routine_name);
		UCHAR* pName = {};
		if (originalFunctionAddr) {
			PsGetProcessImageFileNameType _psGetProcessImageFileName = (PsGetProcessImageFileNameType)originalFunctionAddr;
			pName = _psGetProcessImageFileName(eps);
			LogInfo("%s|%s|%d|%s", IoControlCode == IOCTL_AFD_SEND ? "T" : "U", pName, sbuf->len, buffer);
		}
		else {
			LogInfo("%s|%d|%s", IoControlCode == IOCTL_AFD_SEND ? "T" : "U", sbuf->len, buffer);
		}
		// udp
		if (IoControlCode == IOCTL_AFD_SEND_DATAGRAM && ((AFD_Wsbuf*)sendRecvInfo->BufferArray)->len >= 2000) {
			((AFD_Wsbuf*)sendRecvInfo->BufferArray)->buf = 0;
			((AFD_Wsbuf*)sendRecvInfo->BufferArray)->len = 1;
			LogInfo("Transfer %s|%s|%d", IoControlCode == IOCTL_AFD_SEND ? "T" : "U", pName, sbuf->len);
		}
		// tcp
		if (IoControlCode == IOCTL_AFD_SEND && ((AFD_Wsbuf*)sendRecvInfo->BufferArray)->len >= 2000) {
			((AFD_Wsbuf*)sendRecvInfo->BufferArray)->buf = 0;
			((AFD_Wsbuf*)sendRecvInfo->BufferArray)->len = 1;
			LogInfo("Transfer %s|%s|%d", IoControlCode == IOCTL_AFD_SEND ? "T" : "U", pName, sbuf->len);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// return STATUS_ACCESS_VIOLATION;
	}
	return OriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

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
		auto pid = (ULONG)PsGetCurrentProcessId();
		

		LogInfo("PID=%d CreateFile FileName=%s, ", pid, ObjectAttributes->ObjectName->Buffer);
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