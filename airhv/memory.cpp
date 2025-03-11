#include <ntifs.h>
#include "hypervisor_gateway.h"
#include "log.h"
#include "hookfunction.h"
#include <stdio.h>
#include "adf_io.h"
#include "NtStruct.h"
#include "dispatcher.h"

OriginalMmCopyVirtualMemoryType GetMmCopyVirtualMemoryType() {
    if (OriginalMmCopyVirtualMemory != nullptr) {
        return OriginalMmCopyVirtualMemory;
    }
    UNICODE_STRING routine_name;
    RtlInitUnicodeString(&routine_name, L"MmCopyVirtualMemory");
    PVOID originalFunctionAddr = MmGetSystemRoutineAddress(&routine_name);
    return (OriginalMmCopyVirtualMemoryType)originalFunctionAddr;
}

NTSTATUS ReadMem(MemData* mData) {
    PEPROCESS SourceProcess;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)mData->pid, &SourceProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    SIZE_T bytesCopied = 0;
    OriginalMmCopyVirtualMemoryType _CopyMemory = GetMmCopyVirtualMemoryType();
    status = _CopyMemory(
        SourceProcess,
        mData->address,
        PsGetCurrentProcess(),  // 目标进程为当前内核空间
        mData->buff,
        mData->size,
        UserMode,               // 源地址为用户态
        &bytesCopied
    );
    ObDereferenceObject(SourceProcess);  // 释放 EPROCESS 引用计数
    return (bytesCopied == mData->size) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

NTSTATUS WriteMem(MemData* mData) {
    PEPROCESS SourceProcess;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)mData->pid, &SourceProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    SIZE_T bytesCopied = 0;
    OriginalMmCopyVirtualMemoryType _CopyMemory = GetMmCopyVirtualMemoryType();
    status = _CopyMemory(
        PsGetCurrentProcess(),  // 当前进程为当前内核空间
        mData->buff,
        SourceProcess,
        mData->address,
        mData->size,
        UserMode,               // 源地址为用户态
        &bytesCopied
    );
    ObDereferenceObject(SourceProcess);  // 释放 EPROCESS 引用计数
    return (bytesCopied == mData->size) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}