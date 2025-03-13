#pragma warning( disable : 4201 4244)
#include <ntifs.h>
#include <stdio.h>
#include "hypervisor_gateway.h"
#include "log.h"
#include "hookfunction.h"

#include "adf_io.h"
#include "NtStruct.h"
#include "dispatcher.h"
#include "utils.h"

HookGlobalData hgData;

typedef UCHAR* (*PsGetProcessImageFileNameType)(PEPROCESS Process);

OriginalMmCopyVirtualMemoryType OriginalMmCopyVirtualMemory;
OriginalNtCreateFileType OriginalNtCreateFile;
OriginalNtOpenProcessType OriginalNtOpenProcess;
OriginalMmIsAddressValidType OriginalMmIsAddressValid;
OriginalMemmoveType OriginalMemmove;
OriginalProbeForReadType OriginalProbeForRead;
OriginalNtDeviceIoControlFileType OriginalNtDeviceIoControlFile;
RtlWalkFrameChainType OriginalRtlWalkFrameChain;;


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

ULONG HookedRtlWalkFrameChain(
	_Out_writes_(Count - (Flags >> RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT)) PVOID* Callers,
	_In_ ULONG Count,
	_In_ ULONG Flags
);


HookStruct hsarr[] = {
	{ L"NtCreateFile", HookedNtCreateFile, (void**)&OriginalNtCreateFile },
	{ L"NtOpenProcess", HookedNtOpenProcess, (void**)&OriginalNtOpenProcess},
	{ L"MmIsAddressValid", HookedMmIsAddressValid, (void**)&OriginalMmIsAddressValid },
	{ L"MmCopyVirtualMemory", HookedMmCopyVirtualMemory, (void**)&OriginalMmCopyVirtualMemory },
	{ L"ProbeForRead", HookedProbeForRead, (void**)&OriginalProbeForRead },
	{ L"NtDeviceIoControlFile", HookedNtDeviceIoControlFile, (void**)&OriginalNtDeviceIoControlFile },
	{ L"RtlWalkFrameChain", HookedRtlWalkFrameChain,(void**)&OriginalRtlWalkFrameChain},
};

ULONG HookedRtlWalkFrameChain(
	_Out_writes_(Count - (Flags >> RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT)) PVOID* Callers,
	_In_ ULONG Count,
	_In_ ULONG Flags // 用户态1 内核态0
) {
	ULONG capturedFrames = OriginalRtlWalkFrameChain(Callers, Count, Flags);
	if (Flags == 0) {
		for (int i = 0; i < capturedFrames; i++) {
			if (Callers[i] >= hgData.regionStart && Callers[i] <= hgData.regionEnd) {
				Callers[i] = 0x0; // 暂时这样处理
			}
		}
	}
	if (Flags == 1) {
		if ((ULONG)PsGetCurrentProcessId() == hgData.pid) {
			for (int i = 0; i < capturedFrames; i++) {
				if (Callers[i] >= hgData.userModelRegionStart && Callers[i] <= hgData.userModelRegionEnd) {
					Callers[i] = 0x0; // 暂时这样处理
				}
			}
		}
	}
	return capturedFrames;
}


//void HookedMemmove(_Out_writes_bytes_all_opt_(_Size) void* _Dst, _In_reads_bytes_opt_(_Size) const void* _Src, _In_ size_t _Size) {
//	LogInfo("HookedMemmove dst=%xll src=%xll size=%xll", _Dst, _Src, _Size);
//	OriginalMemmove(_Dst, _Src, _Size);
//}


UNICODE_STRING UserModuleAddress(int i, PVOID address) {
	// 用户模块检测（需进程上下文）
	PEPROCESS process = PsGetCurrentProcess();
	UNICODE_STRING routine_name;
	RtlInitUnicodeString(&routine_name, L"PsGetProcessPeb");
	PVOID PsGetProcessPebAddr = MmGetSystemRoutineAddress(&routine_name);
	typedef PVOID(*_PsGetProcessPebType)(_In_ PEPROCESS Process);

	_PsGetProcessPebType _PsGetProcessPeb = (_PsGetProcessPebType)PsGetProcessPebAddr;
	UNICODE_STRING moduleName{};
	__try {
		if (_PsGetProcessPeb(process) && (ULONG_PTR)address < (ULONG_PTR)MmHighestUserAddress)
		{
			PPEB64 peb = (PPEB64)_PsGetProcessPeb(process);
			PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;

			for (PLIST_ENTRY entry = head->Flink; entry != head; entry = entry->Flink) {
				PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if ((ULONG_PTR)address >= (ULONG_PTR)module->DllBase &&
					(ULONG_PTR)address < (ULONG_PTR)module->DllBase + module->SizeOfImage)
				{
					moduleName = module->BaseDllName;
					auto offset = (ULONG_PTR)address - (ULONG_PTR)module->DllBase;
					// LogInfo("Frame [USER]  %d, 0x%p -> %wZ + %xll\n", i, address, moduleName, offset);
					return moduleName;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		LogInfo("Frame  [UNKNOWN] 0x%p\n",  address);
	}
	return moduleName;

}

ULONG GetTicket() {
	LARGE_INTEGER ticketCount;
	KeQueryTickCount(&ticketCount);
	auto tick = KeQueryTimeIncrement();
	return (ticketCount.QuadPart * tick) / 10000; // 毫秒
}

ULONG64 startTicket;

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
	ANSI_STRING  DNF, SGuard64, ProcessImageName;
	RtlInitAnsiString(&DNF, "DNF.exe");
	RtlInitAnsiString(&SGuard64, "SGuard64.exe");
	// 初始化进程镜像名称字符串
	RtlInitAnsiString(&ProcessImageName, (PCSZ)pName);
	if(!RtlEqualString(&ProcessImageName, &DNF, FALSE) && !RtlEqualString(&ProcessImageName, &SGuard64, FALSE)) {
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
			// LogInfo("%s|%s|%d|%s", IoControlCode == IOCTL_AFD_SEND ? "T" : "U", pName, sbuf->len, buffer);
		}
		else {
			LogInfo("%s|%d|%s", IoControlCode == IOCTL_AFD_SEND ? "T" : "U", sbuf->len, buffer);
		}
		// SGuard64 的udp 直接拦截
		if (IoControlCode == IOCTL_AFD_SEND_DATAGRAM && RtlEqualString(&ProcessImageName, &SGuard64, FALSE)) {
			return NTSTATUS(true);
		}
		// 判断是否passBy
		bool isPassBy = false;
		PETHREAD pThread = PsGetCurrentThread();
		PVOID stackFrames[6] = { 0 };
		ULONG capturedFrames = RtlWalkFrameChain(stackFrames, 6, 0x1);
		auto moduleName = UserModuleAddress(4, stackFrames[4]);
		UNICODE_STRING terSafeName;
		RtlInitUnicodeString(&terSafeName, L"TerSafe.dll");
		if (RtlCompareUnicodeString(&terSafeName, &moduleName, FALSE)) {
			isPassBy = true;
		}
		if (isPassBy) {
			LogInfo("From TerSafe.dll %s|%s|%d|%s", IoControlCode == IOCTL_AFD_SEND ? "T" : "U", pName, sbuf->len, buffer);
			// udp的不属于 340 和 436 的
			if (IoControlCode == IOCTL_AFD_SEND_DATAGRAM && sbuf->len != 340 && sbuf->len != 436 ) {
				return NTSTATUS(true);
			}
			// [0, 1, 6, 9, 10, 11, 13, 21, 23, 24, 29, 31, 32, 35, 37, 38, 42, 45, 53, 54, 56, 61, 69, 73, 75, 77, 78, 80, 85, 87, 92, 93, 96, 101, 103, 109, 111, 112, 113, 117, 119, 121, 125, 126, 127, 128, 129, 130, 133, 135, 136, 138, 139, 141, 142, 144, 149, 151, 152, 157, 160, 165, 166, 170, 171, 173, 174, 176, 181, 182, 185, 189, 190, 191, 192, 197, 200, 205, 208, 211, 213, 221, 222, 224, 225, 229, 237, 238, 242, 245, 246, 253, 258, 261, 262, 265, 268, 269, 270, 273, 277, 280, 289, 292, 293, 300, 301, 305, 309, 313, 317, 318, 321, 322, 325, 326, 327, 328, 329, 331, 333, 337, 339, 341, 349, 350, 353, 354, 357, 359, 365, 369, 372, 373, 375, 376, 379, 380, 381, 382, 383, 384, 385, 386, 389, 401, 405, 413, 417, 418, 421, 433, 449, 453, 457, 458, 459, 460, 461, 462, 465, 477, 481, 497, 511, 513, 517, 520, 528, 529, 545, 557, 561, 577, 593, 609, 625, 641, 657, 679, 687, 689, 703, 705, 737, 769, 785, 807, 817, 833, 849, 881, 897, 913, 929, 1089, 1105, 1121, 1137, 1153, 1229, 1232, 1234, 1329, 1341, 1345, 1388, 1505, 1520, 1713, 1729,
			// 2093, 2321, 2337, 2429, 2477, 2493, 2961, 2977, 3009, 3025, 3037, 3053, 3069, 3421, 3437, 3453, 3469, 4147, 4151, 4614]

			// 4614
			int blockNums[] = { 
				// 529, 557, 561, 577, 585, 593, 625, 641, 657, 679, 687, 689, 703, 737, 769, 807, 833, 1153, 1329, 1341, 1345, 1729,
				520,  557,  687,  703,  807,  1341,
				2337, 2429, 2477, 2493, 2929, 2961, 2977, 2993, 3009, 3025, 3037, 3053, 3069, 3421, 3437, 3453, 3469, 3629, 4147, 4151};
			// dnf
			if (IoControlCode == IOCTL_AFD_SEND && RtlEqualString(&ProcessImageName, &DNF, FALSE)) {
				bool block = true;
				for (const auto n : blockNums) {
					if (sbuf->len == n) {
						block = false;
					}
				}
				if (block && sbuf->len > 2300) {
					LogInfo("BLOCK TerSafe.dll %s|%s|%d", IoControlCode == IOCTL_AFD_SEND ? "T" : "U", pName, sbuf->len);
					// int offsetBegin = 200;
					//PVOID start = (PVOID)((ULONG64)sbuf->buf + offsetBegin);
					//RtlFillMemory(start , max(sbuf->len - offsetBegin - 100, 100), 0x00);
					// NTSTATUS status;
					ProbeForRead(IoStatusBlock, sizeof(IoStatusBlock), 1);
					IoStatusBlock->Information = sbuf->len;
					IoStatusBlock->Pointer = 0;
					IoStatusBlock->Status = 0;
					return STATUS_SUCCESS;

					/*status = OriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
					ULONG_PTR info = IoStatusBlock->Information;
					PVOID ponit = IoStatusBlock->Pointer;
					NTSTATUS iostatus = IoStatusBlock->Status;
					LogInfo("IoStatusBlock: info %d, ponit %d, status %d, outBuffer %p, outBufferLen %d", info, ponit, iostatus, OutputBuffer, OutputBufferLength);
					return status;*/
				}
				
			}
			


			/*
			if (IoControlCode == IOCTL_AFD_SEND && RtlEqualString(&ProcessImageName, &DNF, FALSE)) {
				if (sbuf->len > 517 
					&& sbuf->len != 1341 
					&& sbuf->len != 687 
					&& sbuf->len != 703 
					&& sbuf->len != 807
					&& sbuf->len != 557 
					&& sbuf->len != 520
					&& sbuf->len != 4147
					) {
					LogInfo("BLOCK TerSafe.dll %s|%s|%d", IoControlCode == IOCTL_AFD_SEND ? "T" : "U", pName, sbuf->len);
					PVOID start = (PVOID)((ULONG64)sbuf->buf + 200);
					RtlFillMemory(start, max(sbuf->len - 300, 0x10), 0x00);
					// return NTSTATUS(true);
				}
				
			}
			*/
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
	  // return STATUS_ACCESS_VIOLATION;
	}
	return OriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

}





void HookAllNtFunction() {
	// LogInfo("Start HookAllFunction~");
	// 隐藏
	for (const auto& hs : hsarr) {
		PVOID originalFunctionAddr = GetKernelExportAddr(hs.SourceString);
		if (!originalFunctionAddr) {
			LogError("MmGetSystemRoutineAddress Get Address Fail %s", hs.SourceString);
			break;
		}
		if (!hvgt::hook_function(originalFunctionAddr, hs.hookFunction, hs.originFunction)) {
			LogError("Couldn't hook %s", hs.SourceString);
			break;
		}
		else {
			LogInfo("Hook Function Success %s", hs.SourceString);
		}
	}
	LogInfo("HookAllFunction Success!");
}


NTSTATUS HookedMmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize)
{
	if (hgData.pid == 0) {
		return OriginalMmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, BufferSize, PreviousMode, ReturnSize);
	}
	// 判断被读取的进程是否是被保护的进程
	if ((ULONG)PsGetProcessId(SourceProcess) == hgData.pid) {
		if (SourceAddress  > hgData.regionStart && SourceAddress < hgData.regionEnd){
			RtlFillMemory(TargetAddress, BufferSize, 0xCC);
			return STATUS_SUCCESS;
		}
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
			const auto Pid = (ULONG)ClientId->UniqueProcess;
			const auto cPid = (ULONG)PsGetCurrentProcessId();
			// 用户态自己打开自己
			if (Pid == cPid) {
				return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
			}
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
	//// 通讯使用
	if (RouteDispatcher(EaBuffer, EaLength)) {
		return STATUS_INFO_LENGTH_MISMATCH;
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
		// auto pid = (ULONG)PsGetCurrentProcessId();
		// LogInfo("PID=%d CreateFile FileName=%s, ", pid, ObjectAttributes->ObjectName->Buffer);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}



BOOLEAN HookedMmIsAddressValid(_In_ PVOID VirtualAddress) {
	// 内核层
	if (hgData.regionStart != 0 && hgData.regionEnd != 0) {
		// 在区间
		if (VirtualAddress >= hgData.regionStart && VirtualAddress <= hgData.regionEnd) {
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