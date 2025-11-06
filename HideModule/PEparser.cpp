#include "PEparser.h"
#include <stdio.h>

BOOL LoadFile(const char* filepath,PE_CONTEXT* pctx) {
	// check param
	if (!filepath || !pctx) {
		printf("Missing Param, shit\n");
		return FALSE;
	}
	ZeroMemory(pctx, sizeof(PE_CONTEXT));

	// open file

	HANDLE handle = CreateFileA(
		filepath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (handle == INVALID_HANDLE_VALUE) {
		printf("Can't Open File\n");
		ZeroMemory(pctx, sizeof(PE_CONTEXT));
		return FALSE;
	}

	pctx->hFile = handle;

	// get file size
	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(handle, NULL);
	if (dwFileSize == INVALID_FILE_SIZE) {
		printf("Can't get file size\n");
		ZeroMemory(pctx, sizeof(PE_CONTEXT));
		return FALSE;
	}

	pctx->FileSize = dwFileSize;

	// alloc and readfile
	
	PBYTE tempBuffer = (PBYTE)VirtualAlloc(
		NULL,
		dwFileSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (!tempBuffer) {
		printf("alloc fail\n");
		ZeroMemory(pctx, sizeof(PE_CONTEXT));
		return FALSE;
	}

	DWORD dwByteRead = 0;
	if (!ReadFile(handle, tempBuffer, dwFileSize, &dwByteRead, NULL) || dwByteRead != dwFileSize) {
		printf("Can't read file\n");
		ZeroMemory(pctx, sizeof(PE_CONTEXT));
		return FALSE;
	}

	pctx->FileBuffer = tempBuffer;

	if (!FileToImage(pctx)) {
		printf("ERROR:Can't FileToImage\n");
		EraseTraces(pctx);
		return FALSE;
	}

	
}

BOOL FileToImage(PE_CONTEXT* pctx)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pctx->FileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("ERROR:IS NOT A PE FILE,WRONG DOS HEADER\n");
		EraseTraces(pctx);
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pctx->FileBuffer + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("ERROR:IS NOT A PE FILE,WRONG NT HEADER\n");
		EraseTraces(pctx);
		return FALSE;
	}

	if (!(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
		printf("ERROR:IS NOT A DLL\n");
		EraseTraces(pctx);
		return FALSE;
	}

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(IMAGE_FIRST_SECTION(pNtHeaders));

	DWORD dwImageSize = pNtHeaders->OptionalHeader.SizeOfImage;
	pctx->ImageSize = dwImageSize;
	PBYTE tempBuffer = (PBYTE)VirtualAlloc(
		NULL,
		dwImageSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (!tempBuffer) {
		printf("Alloc Fail\n");
		ZeroMemory(pctx, sizeof(PE_CONTEXT));
		return FALSE;
	}
	pctx->ImageBuffer = tempBuffer;

	DWORD dwHeaderSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
	memcpy(pctx->ImageBuffer, pctx->FileBuffer, dwHeaderSize);

	for (size_t i = 0; i < pNtHeaders->FileHeader.NumberOfSections;i++) {
		if (pSectionHeader[i].Misc.VirtualSize > 0) {
			memcpy(
				pctx->ImageBuffer + pSectionHeader[i].VirtualAddress,
				pctx->FileBuffer + pSectionHeader[i].PointerToRawData,
				min(pSectionHeader[i].Misc.VirtualSize,pSectionHeader[i].SizeOfRawData)
			);
		}
	}
	
	return TRUE;
}

VOID EraseTraces(PE_CONTEXT* pctx) {
	if (pctx->FileBuffer != NULL) {
		VirtualFree(pctx->FileBuffer, 0, MEM_RELEASE);
		pctx->FileBuffer = 0;
		pctx->FileSize = 0;
	}

	if (pctx->ImageBuffer != NULL) {
		VirtualFree(pctx->ImageBuffer, 0, MEM_RELEASE);
		pctx->ImageBuffer = 0;
		pctx->ImageSize = 0;
	}

	if (pctx->hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(pctx->hFile);
	}

	if (pctx->RemoteBaseAddress) {
		if (!VirtualFreeEx(
			pctx->RemoteHandle,
			pctx->RemoteBaseAddress,
			0,
			MEM_RELEASE
		)) {
			printf("ERROR:Can't Free memory in remote process,Is it 2012.12.21 now?\n");
		}
	}

	if (pctx->RemoteHandle) {
		CloseHandle(pctx->RemoteHandle);
	}
}

