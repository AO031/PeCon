#pragma once
#include "PEparser.h"
#include <Windows.h>


BOOL MapDllToProcess(WORD ProcessId, PE_CONTEXT* pctx);
BOOL FixImport(PE_CONTEXT* pctx);
BOOL FixRelocation(PE_CONTEXT* pctx);
BOOL ExcuteDllEntry(PE_CONTEXT* pctx);