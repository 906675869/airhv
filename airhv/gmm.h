#pragma once


typedef struct _GT_MEM_DATA {
	ULONG pid;// 目标进程id
	PVOID address; // 目标进程地址
	ULONG size; // 读取字节多少
	PVOID buff; // 读取的内存|写入的内存
}GT_MEM_DATA, * PMEM;

// 读取虚拟内存
NTSTATUS ReadMem(PMEM mData);

// 写入虚拟内存
NTSTATUS WriteMem(PMEM mData);

// 写入受保护的内存
NTSTATUS WriteProtectedMem(PEPROCESS targetProcess, PVOID UserVa, PVOID Data, SIZE_T Size);