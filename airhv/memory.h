#pragma once
#include "hookfunction.h"

// 读取用户虚拟内存
NTSTATUS ReadMem(MemData* mData);

// 写入用户虚拟内存
NTSTATUS WriteMem(MemData* mData);