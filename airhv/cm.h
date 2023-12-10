#pragma once

#define CM_TYPE_BASE   'EF00'
#define CM_TYPE_TEST   'EF00'
#define CM_TYPE_MODULE 'EF01'
#define CM_TYPE_READ   'EF02'
#define CM_TYPE_WRITE  'EF03'

#define CM_TYPE_KDCLASS  'EF04'
#define CM_TYPE_MUCLASS  'EF05'

#define CM_TYPE_MODULE_HASH 'EF06'
#define CM_TYPE_PROTECT_PROCESS 'EF07'




#define ERROR_SUCCESS				 0xE0000420
#define ERROR_FAIL					 0xE0000421

#define ERROR_FAIL_INVALID_BUFFER    0xE0000432
#define ERROR_FAIL_READ_ERROR    0xE0000433
#define ERROR_FAIL_WRITE_ERROR    0xE0000434
#define ERROR_FAIL_KD_ERROR    0xE0000435


typedef struct _DriverData {

	PVOID kernelBase;

}DriverData, * PDriverData;

extern DriverData driverData;

typedef struct _RegisterNotifyBuffer {
	BOOLEAN Enable;
	PVOID   HookPoint;
	PVOID   Buffer;
	LARGE_INTEGER Cookie;

}RegisterNotifyBuffer, * PRegisterNotifyBuffer;

extern RegisterNotifyBuffer registerNotifyBuffer;


typedef struct _GT_MODULE_DATA {
	ULONG pid; // 进程id
	PCWSTR moduleName; // 模块名称
	PVOID outBuffer; // 输出
}GT_MODULE_DATA, * PGT_MODULE_DATA;


typedef struct _GT_MODULE_HASH_DATA {
	ULONG pid; // 进程id
	ULONG moduleHash; // 模块名称
	PVOID outBuffer; // 输出
}GT_MODULE_HASH_DATA, * PGT_MODULE_HASH_DATA;


typedef struct _KEYBOARD_DATA {
	USHORT UnitId;

	USHORT MakeCode;

	USHORT Flags;

	USHORT Reserved;

	ULONG ExtraInformation;

} KEYBOARD_DATA, * PKEYBOARD_DATA;

typedef struct _GT_KEYBOARD_INPUT_DATA {
	ULONG pid; // 进程id
	KEYBOARD_DATA DT;
}GT_KEYBOARD_INPUT_DATA, * PGT_KEYBOARD_INPUT_DATA;


typedef struct _MOUSE_DATA {

	USHORT UnitId;

	USHORT Flags;

	union {
		ULONG Buttons;
		struct {
			USHORT  ButtonFlags;
			USHORT  ButtonData;
		};
	};

	ULONG RawButtons;

	LONG LastX;

	LONG LastY;

	ULONG ExtraInformation;

} MOUSE_DATA, * PMOUSE_DATA;


typedef struct _GT_MOUSE_DATA {
	ULONG pid; // 进程id
	MOUSE_DATA DT;
}GT_MOUSE_DATA, * PGT_MOUSE_DATA;


typedef struct _GT_PROCESS_DATA {
	ULONG pid;
}GT_PROCESS_DATA, * PGT_PROCESS_DATA;



NTSTATUS RegisterNotifyInit(BOOLEAN Enable);