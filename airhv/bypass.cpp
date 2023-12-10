#include "utils.h"

#include "bypass.h"
#include "hypervisor_gateway.h"


typedef BOOLEAN(*fn_MmIsAddressValidType)(
	_In_ PVOID VirtualAddress
	);

fn_MmIsAddressValidType fMmIsAddressValid;

// PVOID PKA_LIST;

PROTECT_KERNEL_ADDR PKA;

NTSTATUS ProtectKernelAddrInit(bool enable) {
	if (enable) {
		PVOID mma = GetKernelFunction(L"MmIsAddressValid");
		if (!mma) {
			return STATUS_UNSUCCESSFUL;
		}
		if (!hvgt::hook_function(mma, DetourMmAddressValid, (void**)&fMmIsAddressValid)) {
			return STATUS_UNSUCCESSFUL;
		}
	}
	else {
		PVOID mma = GetKernelFunction(L"MmIsAddressValid");
		hvgt::unhook_function(mma);
	}
}

NTSTATUS AddProtectKernelAddr(PPROTECT_KERNEL_ADDR kadr) {
	RtlCopyMemory(&PKA, kadr, sizeof(PROTECT_KERNEL_ADDR));
	return STATUS_SUCCESS;

}

BOOLEAN DetourMmAddressValid(PVOID VirtualAddress) {
	if (PKA.Start == 0 || PKA.Start == PKA.End) {
		return fMmIsAddressValid(VirtualAddress);
	}
	if (VirtualAddress >= PKA.Start && VirtualAddress < PKA.End) {
		return false;
	}
	return fMmIsAddressValid(VirtualAddress);
}

typedef NTSTATUS(*fn_ObReferenceObjectByHandleWithTag)(
	HANDLE Handle,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	ULONG Tag,
	PVOID* Object,
	POBJECT_HANDLE_INFORMATION HandleInformation
	);

ULONG PROTECT_PROCESS_ID;

fn_ObReferenceObjectByHandleWithTag fObReferenceObjectByHandleWithTag;


NTSTATUS ProtectProcessInit(bool enable) {
	// 开关都要清数据
	PROTECT_PROCESS_ID = 0;
	if (enable) {
		DbgPrint("ProtectProcessInit#start");
		PVOID mma = GetKernelFunction(L"ObReferenceObjectByHandleWithTag");
		if (!mma) {
			DbgPrint("ProtectProcessInit#ObReferenceObjectByHandleWithTag Function get Fail");
			return STATUS_UNSUCCESSFUL;
		}
		if (!hvgt::hook_function(mma, DetourObReferenceObjectByHandleWithTag, (void**)&fObReferenceObjectByHandleWithTag)) {
			return STATUS_UNSUCCESSFUL;
		}
	}
	else {
		PVOID mma = GetKernelFunction(L"ObReferenceObjectByHandleWithTag");
		if (!mma) {
			return STATUS_UNSUCCESSFUL;
		}
		hvgt::unhook_function(mma);
	}
}

NTSTATUS AddProtectProcess(ULONG ProtectedId) {
	// 空的话就保护自己
	ProtectedId = ProtectedId == 0 ? (ULONG)PsGetCurrentProcessId() : ProtectedId;
	DbgPrint("AddProtectProcess#add process %d", ProtectedId);
	PROTECT_PROCESS_ID = ProtectedId;
	return STATUS_SUCCESS;
}


NTSTATUS DetourObReferenceObjectByHandleWithTag(
	HANDLE Handle,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	ULONG Tag,
	PVOID* Object,
	POBJECT_HANDLE_INFORMATION HandleInformation
) {
	NTSTATUS status = STATUS_SUCCESS;
	
	// 对象类型非进程或线程 或 无守护进程
	if ((ObjectType != *PsProcessType && ObjectType != *PsThreadType) || PROTECT_PROCESS_ID == 0) {
		return fObReferenceObjectByHandleWithTag(
			Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation
		);
	}
	// 调用原始函数获取对象指针（不增加引用计数）
	status = fObReferenceObjectByHandleWithTag(
		Handle, 0, ObjectType, AccessMode, Tag, Object, HandleInformation
	);
	HANDLE cPid = PsGetCurrentProcessId();
	// DbgPrint("DetourObReferenceObjectByHandleWithTag#invoke");
	if (NT_SUCCESS(status)) {
		// 检查是否为进程/线程对象
		if (ObjectType == *PsProcessType) {
			// 获取目标对象属性（以进程为例）
			PEPROCESS targetProcess = (PEPROCESS)*Object;
			HANDLE targetPid = PsGetProcessId(targetProcess);
			// 查询是否受保护的进程
			// 未设置受保护进程|自己操作自己
			if ((ULONG)targetPid != (ULONG)cPid &&(ULONG)targetPid == PROTECT_PROCESS_ID) {
				ObDereferenceObject(*Object); // 释放临时引用
				return STATUS_ACCESS_DENIED;  // 拒绝访问
			}
		}
		if (ObjectType == *PsThreadType) {
			PETHREAD targetThread = (PETHREAD)*Object;
			PEPROCESS targetProcess = PsGetThreadProcess(targetThread);
			HANDLE targetPid = PsGetProcessId(targetProcess);
			// 查询是否受保护的进程
			if ((ULONG)targetPid != (ULONG)cPid && (ULONG)targetPid == PROTECT_PROCESS_ID) {
				ObDereferenceObject(*Object); // 释放临时引用
				return STATUS_ACCESS_DENIED;  // 拒绝访问
			}
		}
	}
	// ObDereferenceObject(*Object);
	// 正常流程：重新调用原始函数并传递实际权限
	return fObReferenceObjectByHandleWithTag(
		Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation
	);


}



PVOID ProtectFileName;

typedef NTSTATUS(*fn_NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength
	);

fn_NtCreateFile fNtCreateFile;

NTSTATUS ProtectFileInit(bool enable) {
	if (enable) {
		DbgPrint("ProtectFileInit#start");
		ProtectFileName = ExAllocatePoolWithTag(NonPagedPoolNx, 100, 'NetF');
		if (!ProtectFileName) {
			return STATUS_UNSUCCESSFUL;
		}
		PVOID mma = GetKernelFunction(L"NtCreateFile");
		if (!mma) {
			ExFreePoolWithTag(ProtectFileName, 'NetF');
			ProtectFileName = nullptr;
			return STATUS_UNSUCCESSFUL;
		}
		if (!hvgt::hook_function(mma, DetourNtCreateFile, (void**)&fNtCreateFile)) {
			return STATUS_UNSUCCESSFUL;
		}
	}
	else {
		if (ProtectFileName) {
			ExFreePoolWithTag(ProtectFileName, 'NetF');
		}
		PVOID mma = GetKernelFunction(L"NtCreateFile");
		if (!mma) {
			hvgt::unhook_function(mma);
		}
	}

	return STATUS_SUCCESS;
}

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
)
{
	if (ProtectFileName == nullptr || wcslen((PWSTR)ProtectFileName) == 0) {
		return fNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}
	__try
	{
		ProbeForRead(FileHandle, sizeof(HANDLE), 1);
		ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
		ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
		ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
		if (wcsstr(ObjectAttributes->ObjectName->Buffer, (PWSTR)ProtectFileName) != NULL)
		{
			return STATUS_INVALID_BUFFER_SIZE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return fNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS ProtectFile(PWSTR fileName) {
	if (!ProtectFileName) {
		return STATUS_UNSUCCESSFUL;
	}
	int len = (wcslen(fileName) + 1) * sizeof(WCHAR);
	if (len > 100) {
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(ProtectFileName, 100);
	// 复制到内核中
	RtlCopyMemory(ProtectFileName, fileName, len);
	UNICODE_STRING pUFile;
	RtlInitUnicodeString(&pUFile, (PCWSTR)ProtectFileName);
	DbgPrint("Protect File %wZ", &pUFile);
	return STATUS_SUCCESS;
}