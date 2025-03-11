#pragma once
#include "hookfunction.h"

extern PDRIVER_OBJECT gdriver_object;

bool RouteDispatcher(PVOID buffer, ULONG length);