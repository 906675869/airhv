#pragma warning( disable : 4201 4805)
#include "dispatcher.h"
#include "hookfunction.h"
#include <ntddk.h>
#include <intrin.h>
#include "log.h"
#include "ntapi.h"
#include "hypervisor_routines.h"
#include "hypervisor_gateway.h"
#include "vmm.h"
#include "memory.h"


bool RouteDispatcher(PVOID buffer, ULONG length) {
	auto PreMode = ExGetPreviousMode();
	// 基本验证
	if (PreMode != UserMode || buffer == nullptr || length != sizeof(ConnectData)) {
		return false;
	}
	__try
	{
		ProbeForRead(buffer, sizeof(ConnectData), 1);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	ConnectData* cdata = (ConnectData*)buffer;
	if (cdata->MaskKey != MASK_KEY) {
		return false;
	}
	if (cdata->ConnectType == READ) {
		return NT_SUCCESS(ReadMem((MemData*)cdata->Data));
	}
	if (cdata->ConnectType == WRITE) {
		return NT_SUCCESS(WriteMem((MemData*)cdata->Data));
	}
	// 成功
	return false;
}