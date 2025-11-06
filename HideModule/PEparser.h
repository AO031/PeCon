#pragma once

#include <Windows.h>

typedef struct {
	HANDLE hFile;
	DWORD FileSize;
	PBYTE FileBuffer;
	DWORD ImageSize;
	PBYTE ImageBuffer;

	HANDLE RemoteHandle;
	PBYTE RemoteBaseAddress;
}PE_CONTEXT;

BOOL LoadFile(const char* filepath, PE_CONTEXT* pctx);
BOOL FileToImage(PE_CONTEXT* pctx);
VOID EraseTraces(PE_CONTEXT* pctx);