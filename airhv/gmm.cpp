#include "utils.h"
#include "tools.h"
#include "gmm.h"

typedef NTSTATUS(*fn_MmCopyVirtualMemory)(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

NTSTATUS ReadMem(PMEM mData) {
    PEPROCESS SourceProcess;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)mData->pid, &SourceProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    SIZE_T bytesCopied = 0;
    fn_MmCopyVirtualMemory _CopyMemory = (fn_MmCopyVirtualMemory)GetKernelFunction(L"MmCopyVirtualMemory");
    status = _CopyMemory(
        SourceProcess,
        mData->address,
        PsGetCurrentProcess(),  // 目标进程为当前内核空间
        mData->buff,
        mData->size,
        KernelMode,               // 源地址为用户态
        &bytesCopied
    );
    ObDereferenceObject(SourceProcess);  // 释放 EPROCESS 引用计数
    return (bytesCopied == mData->size) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

NTSTATUS WriteMem(PMEM mData) {
    PEPROCESS targetProcess;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)mData->pid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // 目标地址是否可写
    if (IsWritableEx(targetProcess, mData->address)) {
        // DbgPrint("pid=%d address 0x%p is writable.", mData->pid, mData->address);
        // 目标可写
        SIZE_T bytesCopied = 0;
        fn_MmCopyVirtualMemory _CopyMemory = (fn_MmCopyVirtualMemory)GetKernelFunction(L"MmCopyVirtualMemory");
        status = _CopyMemory(
            PsGetCurrentProcess(),  // 当前进程为当前内核空间
            mData->buff,
            targetProcess,
            mData->address,
            mData->size,
            KernelMode,               // 源地址为用户态
            &bytesCopied
        );
        ObDereferenceObject(targetProcess);  // 释放 EPROCESS 引用计数
        return (bytesCopied == mData->size) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
    }
    // 复制到内核中
    GT_MEM_DATA memCache;
    RtlCopyMemory(&memCache, mData, sizeof(GT_MEM_DATA));

    // 强写内存
    status = WriteProtectedMem(targetProcess, memCache.address, memCache.buff, memCache.size);
    ObDereferenceObject(targetProcess);  // 释放 EPROCESS 引用计数
    return status;
}


// 强写内存
NTSTATUS WriteProtectedMem(PEPROCESS targetProcess, PVOID UserVa, PVOID Data, SIZE_T Size) {
    NTSTATUS status = STATUS_SUCCESS;
    PVOID WriteData = ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, 'NetF');
    if (!WriteData) {
        DbgPrint("WriteProtectedMem#ExAllocatePoolWithTag WriteData Fail");
        return STATUS_UNSUCCESSFUL;
    }
    // 复制内存到 内核中
    RtlCopyMemory(WriteData, Data, Size);

    // DbgPrint("WriteProtectedMem# UserVa=0x%p Data=%s", UserVa, (char*)Data);

    KAPC_STATE ApcState;
    KeStackAttachProcess(targetProcess, &ApcState);
    // create mdl
    PMDL lpMemoryDescriptorList = MmCreateMdl(NULL, UserVa, Size);

    if (lpMemoryDescriptorList != NULL) {
        MmProbeAndLockPages(lpMemoryDescriptorList, KernelMode, IoReadAccess);
        LPVOID lpMappedAddress = MmMapLockedPagesSpecifyCache(lpMemoryDescriptorList, KernelMode, MmCached, NULL, 0, NormalPagePriority);
        if (lpMappedAddress != NULL) {
            // 复制到物理地址映射的mdl
            RtlCopyMemory(lpMappedAddress, WriteData, Size);
            // 解除映射
            MmUnmapLockedPages(lpMappedAddress, lpMemoryDescriptorList);
            status = STATUS_SUCCESS;
        }
        // 解除锁页
        MmUnlockPages(lpMemoryDescriptorList);
        IoFreeMdl(lpMemoryDescriptorList);
    }
    // 解除附加
    KeUnstackDetachProcess(&ApcState);

    ExFreePoolWithTag(WriteData, 'NetF');

    return status;
}