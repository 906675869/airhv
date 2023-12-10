#pragma once

typedef struct _PROTECT_KERNEL_ADDR {
	PVOID Start;
	PVOID End;
} PROTECT_KERNEL_ADDR, * PPROTECT_KERNEL_ADDR;

// 最多10个
NTSTATUS ProtectKernelAddrInit(bool enable);

// 添加内核保护区间到
NTSTATUS AddProtectKernelAddr(PPROTECT_KERNEL_ADDR kadr);

// hook MmAddressValid exec
BOOLEAN DetourMmAddressValid(PVOID VirtualAddress);

// 保护进程
NTSTATUS ProtectProcessInit(bool enable);

NTSTATUS AddProtectProcess(ULONG ProtectedId);

NTSTATUS DetourObReferenceObjectByHandleWithTag(
	HANDLE Handle,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	ULONG Tag,
	PVOID* Object,
	POBJECT_HANDLE_INFORMATION HandleInformation
);

// 保护
NTSTATUS ProtectFileInit(bool enable);

NTSTATUS NTAPI DetourNtCreateFile(
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

NTSTATUS ProtectFile(PWSTR fileName);