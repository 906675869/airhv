#include "utils.h"

#include "bypass.h"
#include "hypervisor_gateway.h"


typedef BOOLEAN(*fn_MmIsAddressValidType)(
	_In_ PVOID VirtualAddress
	);

fn_MmIsAddressValidType fMmIsAddressValid;

PVOID PKA_LIST;

NTSTATUS ProtectKernelAddrInit(bool enable) {
	if (enable) {
		PKA_LIST = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(PROTECT_KERNEL_ADDR) * 10, 'NetF');
		if (!PKA_LIST) {
			return STATUS_UNSUCCESSFUL;
		}
		PVOID mma = GetKernelFunction(L"MmIsAddressValid");
		if (!mma) {
			ExFreePoolWithTag(PKA_LIST, 'NetF');
			PKA_LIST = nullptr;
			return STATUS_UNSUCCESSFUL;
		}
		if (!hvgt::hook_function(mma, DetourMmAddressValid, (void**)&fMmIsAddressValid)) {
			ExFreePoolWithTag(PKA_LIST, 'NetF');
			PKA_LIST = nullptr;
			return STATUS_UNSUCCESSFUL;
		}
	}
	else if (PKA_LIST) {
		PVOID mma = GetKernelFunction(L"MmIsAddressValid");
		hvgt::unhook_function(mma);
		ExFreePoolWithTag(PKA_LIST, 'NetF');
		PKA_LIST = nullptr;
	}
}

NTSTATUS AddProtectKernelAddr(PPROTECT_KERNEL_ADDR kadr) {
	if (!PKA_LIST) {
		return STATUS_UNSUCCESSFUL;
	}
	PPROTECT_KERNEL_ADDR kaddr = (PPROTECT_KERNEL_ADDR)PKA_LIST;
	for (int i = 0; i < 10; i++) {
		// 已使用
		if (kaddr->Start != 0 && kaddr->End != 0 && kaddr->Start != kaddr->End) {
			if (i == 9) {
				return STATUS_UNSUCCESSFUL;
			}
			kaddr++;
			continue;
		}
		kaddr->Start = kadr->Start;
		kaddr->End = kadr->End;
		break;
	}
	return STATUS_SUCCESS;

}

BOOLEAN DetourMmAddressValid(PVOID VirtualAddress) {
	PPROTECT_KERNEL_ADDR kaddr = (PPROTECT_KERNEL_ADDR)PKA_LIST;
	for (int i = 0; i < 10; i++) {
		if (kaddr->Start == 0 || kaddr->Start == kaddr->End) {
			break;
		}
		if (VirtualAddress >= kaddr->Start && VirtualAddress < kaddr->End) {
			return false;
		}

		kaddr++;
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

ULONG ProtectedPids[10];

fn_ObReferenceObjectByHandleWithTag fObReferenceObjectByHandleWithTag;


NTSTATUS ProtectProcessInit(bool enable) {
	// 开关都要清数据
	RtlZeroMemory(ProtectedPids, 10);
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
	for (int i = 0; i < 10; i++) {
		if (ProtectedPids[i] == 0) {
			ProtectedPids[i] = ProtectedId;
			break;
		}
	}
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
	HANDLE cPid = PsGetCurrentProcessId();
	if (ObjectType != *PsProcessType && ObjectType != *PsThreadType) {
		return fObReferenceObjectByHandleWithTag(
			Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation
		);
	}
	// 调用原始函数获取对象指针（不增加引用计数）
	status = fObReferenceObjectByHandleWithTag(
		Handle, 0, ObjectType, AccessMode, Tag, Object, HandleInformation
	);
	// DbgPrint("DetourObReferenceObjectByHandleWithTag#invoke");
	if (NT_SUCCESS(status)) {
		// 检查是否为进程/线程对象
		if (ObjectType == *PsProcessType) {
			
			// 获取目标对象属性（以进程为例）
			PEPROCESS targetProcess = (PEPROCESS)*Object;
			HANDLE targetPid = PsGetProcessId(targetProcess);
			// DbgPrint("DetourObReferenceObjectByHandleWithTag#invoke targetPid=%d", (ULONG)targetPid);
			// 查询是否受保护的进程
			for (int i = 0; i < 10; i++) {
				auto ppId = ProtectedPids[i];
				DbgPrint("DetourObReferenceObjectByHandleWithTag[Process]#invoke ProtectedPids[%d]=%d, targetPid=%d",i, (ULONG)ppId, (ULONG)targetPid);
				// 未设置受保护进程|自己操作自己
				if (ppId == 0 || (ULONG)targetPid == (ULONG)cPid) {
					break;
				}
				if ((ULONG)targetPid == ProtectedPids[i]) {
					ObDereferenceObject(*Object); // 释放临时引用
					return STATUS_ACCESS_DENIED;  // 拒绝访问
				}
			}
		}
		if (ObjectType == *PsThreadType) {
			PETHREAD targetThread = (PETHREAD)*Object;
			PEPROCESS targetProcess = PsGetThreadProcess(targetThread);
			HANDLE targetPid = PsGetProcessId(targetProcess);
			// DbgPrint("DetourObReferenceObjectByHandleWithTag#invoke pid=%d", (ULONG)targetPid);
			// 查询是否受保护的进程
			for (int i = 0; i < 10; i++) {
				auto ppId = ProtectedPids[i];
				DbgPrint("DetourObReferenceObjectByHandleWithTag[Thread]#invoke ProtectedPids[%d]=%d, targetPid=%d", i, (ULONG)ppId, (ULONG)targetPid);
				// 未设置受保护进程|自己操作自己
				if (ppId == 0 || (ULONG)targetPid == (ULONG)cPid) {
					break;
				}
				if ((ULONG)targetPid == ProtectedPids[i]) {
					ObDereferenceObject(*Object); // 释放临时引用
					return STATUS_ACCESS_DENIED;  // 拒绝访问
				}
			}

		}
	}
	// 正常流程：重新调用原始函数并传递实际权限
	return fObReferenceObjectByHandleWithTag(
		Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation
	);

}
