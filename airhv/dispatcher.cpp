#pragma warning( disable : 4201 4805)
#include "dispatcher.h"
#include "log.h"
#include "ntapi.h"
#include "memory.h"
#include "kmclass_common.h"
#include "utils.h"

extern "C" {
	NTKERNELAPI
		HANDLE
		PsGetCurrentProcessId(
			VOID
		);
}


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
		LogError("buffer IS NOT READ");
		return false;
	}

	ConnectData* cdata = (ConnectData*)buffer;
	if (cdata->MaskKey != MASK_KEY) {
		LogError("MASK_KEY IS NOT READ");
		return false;
	}
	auto pid = PsGetCurrentProcessId();
	hgData.pid = (ULONG)pid;
	if (cdata->ConnectType == TEST) {
		auto td = (TestData*)cdata->Data;
		td->status = MASK_KEY ^ 0xFF;
		return STATUS_SUCCESS;
	}
	if (cdata->ConnectType == READ) {
		return NT_SUCCESS(ReadMem((MemData*)cdata->Data));
	}
	if (cdata->ConnectType == WRITE) {
		return NT_SUCCESS(WriteMem((MemData*)cdata->Data));
	}
	// 当前是保护文件
	if (cdata->ConnectType == PROTECT_FILE) {
		// todo 判断文件创建是否已经被hook了
		PFILE_PROTECT_DATA filedata = (PFILE_PROTECT_DATA)cdata->Data;
		wchar_t fileName[128];
		RtlCopyMemory(fileName, filedata->fileName, sizeof(filedata->fileName));
		hgData.fileName = fileName;
		return STATUS_SUCCESS;
	}
	// 隐藏当前进程代码段
	if (cdata->ConnectType == HIDE_R3_MEM) {
		AddressRegion region;
		if (NT_SUCCESS(GetUserCodeRange(pid, &region))) {
			hgData.userModelRegionStart = region.start;
			hgData.userModelRegionEnd = region.end;
		};
	}
	//// 键盘
	if (cdata->ConnectType == KEY) {
		//// 搜索键盘
		KEYBOARD_INPUT_DATA* kid = (PKEYBOARD_INPUT_DATA)cdata->Data;
		PKEYBOARD_INPUT_DATA KbdInputDataStart = kid;
		PKEYBOARD_INPUT_DATA KbdInputDataEnd = KbdInputDataStart + 1;
		ULONG InputDataConsumed;
		g_KoMCallBack.KeyboardClassServiceCallback(g_KoMCallBack.KdbDeviceObject,
			KbdInputDataStart,
			KbdInputDataEnd,
			&InputDataConsumed);
		return true;
	}
	// 鼠标
	if (cdata->ConnectType == MOUSE) {
		MOUSE_INPUT_DATA mid = *(PMOUSE_INPUT_DATA)cdata->Data;
		PMOUSE_INPUT_DATA MouseInputDataStart = &mid;
		PMOUSE_INPUT_DATA MouseInputDataEnd = MouseInputDataStart + 1;
		ULONG InputDataConsumed;
		g_KoMCallBack.MouseClassServiceCallback(g_KoMCallBack.MouDeviceObject,
			MouseInputDataStart,
			MouseInputDataEnd,
			&InputDataConsumed);
		return true;
	
	}
	// 模块base
	if (cdata->ConnectType == ConnectType::GET_MODULE_BASE) {
		ModuleData* md = (ModuleData*)cdata->Data;
		md->moduleBase = (PVOID)GetModuleBase(md->pid, md->moduleName);
		return true;
	}
	// 成功
	return false;
}