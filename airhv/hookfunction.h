#pragma once






void HookAllNtFunction();


BOOLEAN HookedMmIsAddressValid(_In_ PVOID VirtualAddress);

struct HookStruct {
	PCWSTR SourceString;
	void* hookFunction;
	void** originFunction;
};

struct HookGlobalData {
	ULONG pid = 1740; // 被保护的进程

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

