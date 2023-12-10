#include "NtStruct.h"
#include "utils.h"
#include "cm.h"
#include "kmclass.h"
#include "gmm.h"
#include "bypass.h"

DriverData driverData;
RegisterNotifyBuffer registerNotifyBuffer;

NTSTATUS RegisterNotify(LPVOID, REG_NOTIFY_CLASS OperationType, PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo) {
	NTSTATUS Status = STATUS_SUCCESS;

	if (OperationType == RegNtPreSetValueKey && PreSetValueInfo->Type >= CM_TYPE_BASE) {
		switch (PreSetValueInfo->Type) {
		case CM_TYPE_TEST:
			if (PreSetValueInfo->Data == NULL) {
				DbgPrint("Connect...");
				Status = ERROR_SUCCESS;
			}
			break;
		case CM_TYPE_MODULE:
			// 获取模块地址
			if (PreSetValueInfo->DataSize == sizeof(GT_MODULE_DATA)) {
				PGT_MODULE_DATA pBuffer = (PGT_MODULE_DATA)PreSetValueInfo->Data;
				if (pBuffer->outBuffer == NULL) {
					Status = ERROR_FAIL_INVALID_BUFFER;
				}
				else {
					*(ULONG64*)pBuffer->outBuffer = (ULONG64)GetModuleBase(pBuffer->pid, pBuffer->moduleName);
					Status = ERROR_SUCCESS;
				}
			}
			break;
		case CM_TYPE_MODULE_HASH:
			if (PreSetValueInfo->DataSize == sizeof(_GT_MODULE_HASH_DATA)) {
				PGT_MODULE_HASH_DATA pBuffer = (PGT_MODULE_HASH_DATA)PreSetValueInfo->Data;
				if (pBuffer->outBuffer == NULL) {
					Status = ERROR_FAIL_INVALID_BUFFER;
				}
				else {
					*(ULONG64*)pBuffer->outBuffer = (ULONG64)GetModuleBaseByHashW(pBuffer->pid, pBuffer->moduleHash);
					Status = ERROR_SUCCESS;
				}
			}
			break;
		case CM_TYPE_READ:
			// 读取内存
			if (PreSetValueInfo->DataSize == sizeof(GT_MEM_DATA)) {
				PMEM pBuffer = (PMEM)PreSetValueInfo->Data;
				if (pBuffer->buff == NULL) {
					Status = ERROR_FAIL_INVALID_BUFFER;
				}
				else {
					if (!NT_SUCCESS(ReadMem(pBuffer))) {
						Status = ERROR_FAIL_READ_ERROR;
					}
					else {
						Status = ERROR_SUCCESS;
					}
				}
			}
			break;
		case CM_TYPE_WRITE:
			// 写入内存
			if (PreSetValueInfo->DataSize == sizeof(GT_MEM_DATA)) {
				PMEM pBuffer = (PMEM)PreSetValueInfo->Data;
				if (pBuffer->buff == NULL) {
					Status = ERROR_FAIL_INVALID_BUFFER;
				}
				else {
					if (!NT_SUCCESS(WriteMem(pBuffer))) {
						Status = ERROR_FAIL_WRITE_ERROR;
					}
					else {
						Status = ERROR_SUCCESS;
					}
				}

			}
			break;
		case CM_TYPE_KDCLASS:
			// 键盘
			if (PreSetValueInfo->DataSize == sizeof(GT_KEYBOARD_INPUT_DATA)) {
				PGT_KEYBOARD_INPUT_DATA pBuffer = (PGT_KEYBOARD_INPUT_DATA)PreSetValueInfo->Data;
				Status = KeyboardInput((PVOID)&pBuffer->DT);
			}
			break;
		case CM_TYPE_MUCLASS:
			// 鼠标
			if (PreSetValueInfo->DataSize == sizeof(GT_MOUSE_DATA)) {
				PGT_MOUSE_DATA pBuffer = (PGT_MOUSE_DATA)PreSetValueInfo->Data;
				// DbgPrint("GT_MOUSE_DATA ButtonFlags=%d Flags=%d \n", pBuffer->DT.ButtonFlags, pBuffer->DT.Flags);
				Status = MouseInput((PVOID)&pBuffer->DT);
			}
			break;
		case CM_TYPE_PROTECT_PROCESS:
			if (PreSetValueInfo->DataSize == sizeof(GT_PROCESS_DATA)) {
				PGT_PROCESS_DATA pBuffer = (PGT_PROCESS_DATA)PreSetValueInfo->Data;
				AddProtectProcess(pBuffer->pid);
			}
			break;
		case CM_TYPE_PROTECT_FILE:
			if (PreSetValueInfo->DataSize == sizeof(GT_FILE_DATA)) {
				PGT_FILE_DATA pBuffer = (PGT_FILE_DATA)PreSetValueInfo->Data;
				ProtectFile(pBuffer->fileName);
			}
		default:
			Status = ERROR_FAIL;
		}
	}
	return Status;
}



NTSTATUS RegisterNotifyInit(BOOLEAN Enable) {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PRegisterNotifyBuffer pRegisterNotifyHookBuffer = &registerNotifyBuffer;

	if (pRegisterNotifyHookBuffer->Enable != Enable) {

		if (pRegisterNotifyHookBuffer->HookPoint == NULL) {
			// "\xFF\xE1" jmp rcx
			// \xFF\x21 jmp [rcx]
			// pRegisterNotifyHookBuffer->HookPoint = SearchSignForImage(driverData.kernelBase, "\xFF\xE1", "xx", 2);
			pRegisterNotifyHookBuffer->HookPoint = SearchSignForImage(driverData.kernelBase, "\xFF\x21", "xx", 2);
		}

		if (pRegisterNotifyHookBuffer->HookPoint != NULL) {

			if (Enable == TRUE) {
				PVOID buffer = ExAllocatePoolWithTag(NonPagedPoolNx, 128, 'NetF');
				if (!buffer) {

					return STATUS_UNSUCCESSFUL;
				}
				*(ULONG64*)buffer = (ULONG64)RegisterNotify;

				pRegisterNotifyHookBuffer->Buffer = buffer;
				Status = CmRegisterCallback((PEX_CALLBACK_FUNCTION)(pRegisterNotifyHookBuffer->HookPoint), buffer, &pRegisterNotifyHookBuffer->Cookie);

				if (NT_SUCCESS(Status)) {

					pRegisterNotifyHookBuffer->Enable = TRUE;
				}
			}

			if (Enable != TRUE) {

				if (pRegisterNotifyHookBuffer->HookPoint != NULL) {

					Status = CmUnRegisterCallback(pRegisterNotifyHookBuffer->Cookie);

					if (pRegisterNotifyHookBuffer->Buffer) {
						ExFreePoolWithTag(pRegisterNotifyHookBuffer->Buffer, 'NetF');
					}
					if (NT_SUCCESS(Status)) {
						pRegisterNotifyHookBuffer->Enable = FALSE;
					}
				}
			}
		}
	}

	if (pRegisterNotifyHookBuffer->Enable == Enable) {

		Status = STATUS_SUCCESS;
	}

	return Status;
}