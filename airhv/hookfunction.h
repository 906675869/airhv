#pragma once
#include <wdm.h>

typedef NTSTATUS(*OriginalMmCopyVirtualMemoryType)(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);


typedef NTSTATUS(*OriginalNtCreateFileType)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength
	);


typedef NTSTATUS(*OriginalNtOpenProcessType)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
	);



typedef BOOLEAN(*OriginalMmIsAddressValidType)(
	_In_ PVOID VirtualAddress
	);


typedef void (*OriginalMemmoveType)(void* _Dst, const void* _Src, size_t _Size);


typedef VOID(*OriginalProbeForReadType)(
	volatile VOID* Address,
	_In_ SIZE_T Length,
	_In_ ULONG Alignment
);

typedef 
NTSTATUS
(*OriginalNtDeviceIoControlFileType)(
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

extern OriginalMmCopyVirtualMemoryType OriginalMmCopyVirtualMemory;
extern OriginalNtCreateFileType OriginalNtCreateFile;
extern OriginalNtOpenProcessType OriginalNtOpenProcess;
extern OriginalMmIsAddressValidType OriginalMmIsAddressValid;
extern OriginalMemmoveType OriginalMemmove;
extern OriginalProbeForReadType OriginalProbeForRead;
extern OriginalNtDeviceIoControlFileType OriginalNtDeviceIoControlFile;





void HookAllNtFunction();


BOOLEAN HookedMmIsAddressValid(_In_ PVOID VirtualAddress);

struct HookStruct {
	PCWSTR SourceString;
	void* hookFunction;
	void** originFunction;
};

struct HookGlobalData {
	ULONG pid = 0; // 被保护的进程

	// 被保护的内核空间
	PVOID regionStart;
	PVOID regionEnd;

	// 被保护的用户控件
	PVOID userModelRegionStart;
	PVOID userModelRegionEnd;

	// 被保护的文件名
	wchar_t* fileName=L"";
};

extern HookGlobalData hgData;

//void UserModuleAddress(PVOID address);

// 定义导出
ULONG GetTicket();



#define MASK_KEY 0x7758258

enum ConnectType {
	TEST,
	PROTECT_FILE, // 保护文件
	HIDE_R3_MEM,// 隐藏R3内存
	HIDE_R0_MEM,// 隐藏R0内存
	READ, // 读取
	WRITE,// 写入
	READ_PHY,// 读取物理内存
	WRITE_PHY,// 写入物理内存
	ALLOC, // 申请内存
	KEY,
	MOUSE
};

struct ConnectData {
	ULONG MaskKey;
	ULONG ConnectType; //ConnectType
	PVOID Data; // MemData KeyData MouseData
};

struct MemData {
	ULONG pid;// 目标进程id
	PVOID address;
	ULONG size;
	PVOID buff; // 读取的内存|写入的内存
};


struct KeyData {



};

struct MouseData {


};