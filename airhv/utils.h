#pragma once




NTSTATUS SafeAllocateString(OUT PUNICODE_STRING result, IN USHORT size);

NTSTATUS SafeInitString(OUT PUNICODE_STRING result, IN PUNICODE_STRING source);

LONG SafeSearchString(IN PUNICODE_STRING source, IN PUNICODE_STRING target, IN BOOLEAN CaseInSensitive);

NTSTATUS StripPath(IN PUNICODE_STRING path, OUT PUNICODE_STRING name);

NTSTATUS StripFilename(IN PUNICODE_STRING path, OUT PUNICODE_STRING dir);

NTSTATUS FileExists(IN PUNICODE_STRING path);

NTSTATUS SearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);

PVOID GetKernelExportAddr(PCWSTR fName);