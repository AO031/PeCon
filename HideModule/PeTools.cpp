#include "PETools.h"
#include <stdio.h>

BOOL MapDllToProcess(WORD ProcessId, PE_CONTEXT* pctx)
{
	if (!ProcessId||!pctx) {
		printf("shit,what a bad param in MapDllToProcess\n");
		return FALSE;
	}

	HANDLE ProcessHandle = OpenProcess(
		PROCESS_ALL_ACCESS,
		TRUE,
		ProcessId
	);

	if (!ProcessHandle) {
		printf("ERROR:Can't Open Process\n");
		EraseTraces(pctx);
		return FALSE;
	}
	pctx->RemoteHandle = ProcessHandle;

	LPVOID Remoteaddress = VirtualAllocEx(
		ProcessHandle,
		NULL,
		pctx->ImageSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!Remoteaddress) {
		printf("ERROR:Can't Alloc in remote process\n");
		EraseTraces(pctx);
		return FALSE;
	}

	pctx->RemoteBaseAddress = (PBYTE)Remoteaddress;

	if (!WriteProcessMemory(
		pctx->RemoteHandle,
		pctx->RemoteBaseAddress,
		pctx->ImageBuffer,
		pctx->ImageSize,
		NULL
	)) {
		printf("ERROR:Can't write in remote process,error code:%d\n", GetLastError());
		EraseTraces(pctx);
		return FALSE;
	}

	if (!FixRelocation(pctx)) {
		printf("ERROR:Can't fix relocation\n");
		EraseTraces(pctx);
		return FALSE;
	}

	if (!FixImport(pctx)) {
		printf("ERROR:Can't fix Import dir\n");
		EraseTraces(pctx);
		return FALSE;
	}

	//ExcuteDllEntry

	return TRUE;
}

BOOL FixImport(PE_CONTEXT* pctx)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pctx->ImageBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("ERROR:IS NOT A PE FILE,WRONG DOS HEADER\n");
		EraseTraces(pctx);
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)
		(pctx->ImageBuffer + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("ERROR:IS NOT A PE FILE,WRONG NT HEADER\n");
		EraseTraces(pctx);
		return FALSE;
	}

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)
		(IMAGE_FIRST_SECTION(pNtHeaders));

	PIMAGE_DATA_DIRECTORY pDataDirectory =
		(PIMAGE_DATA_DIRECTORY)(&pNtHeaders->OptionalHeader.DataDirectory);

	if (pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 ||
		pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
		printf("THIS FILE DON'T HAVE IMPORT\n");
		EraseTraces(pctx);
		return FALSE;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pctx->ImageBuffer + pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (pImport->Name) {
		// loadlibrarya

		HMODULE hkernel32 = GetModuleHandleA("kernel32.dll");
		if (!hkernel32) {
			return FALSE;
		}
		FARPROC loadlibraryaddr = GetProcAddress(hkernel32, "LoadLibraryA");

		PCHAR dllname = (PCHAR)(pctx->ImageBuffer + pImport->Name);
		PBYTE dllnameaddr = (PBYTE)VirtualAllocEx(
			pctx->RemoteHandle,
			NULL,
			strlen(dllname) + 0x1,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);

		if (!dllnameaddr) {
			printf("alloc fail\n");
			EraseTraces(pctx);
			return FALSE;
		}


#if defined(_WIN64)
		unsigned char shellcode[] = {
			0x51,												// push rcx
			0x52,												// push rdx
			0x41,0x50,											// push r8
			0x41,0x51,											// push r9
			0x50,												// push rax
			0x48,0x83,0xec,0x30,								// sub rsp, 0x28        
			0x48,0xb9,0xf0,0xde,0xbc,0x9a,0x78,0x56,0x34,0x12,	// mov rcx, 0x123456789ABCDEF0
			0x48,0xb8,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x7f,	// mov rax, 0x7FFFFFFF00000000
			0xff,0xd0,											// call rax
			0x48,0xb9,0xf0,0xde,0xbc,0x9a,0x78,0x56,0x34,0x12,	// mov rcx, 0x123456789ABCDEF0
			0x48,0x89,0x01,										// mov [rcx], rax
			0x48,0x83,0xc4,0x30,								// add rsp, 0x28
			0x58,												// pop rax
			0x41,0x59,											// pop r9
			0x41,0x58,											// pop r8
			0x5a,												// pop rdx
			0x59,												// pop rcx
			0xc3												// ret
		};														
		*(ULONGLONG*)&shellcode[13] = (ULONGLONG)dllnameaddr;
		*(ULONGLONG*)&shellcode[35] = (ULONGLONG)dllnameaddr;
		*(ULONGLONG*)&shellcode[23] = (ULONGLONG)loadlibraryaddr;
#else
		unsigned char shellcode[] = {
			0x55,						// push ebp
			0x89,0xe5,					// mov ebp, esp
			0xff,0x75,0x08,				// push [ebp+8]
			0xb8,0xff,0xff,0xff,0x7f,	// mov eax, 0x7fffffff 
			0xff,0xd0,					// call eax
			0xb9,0x78,0x56,0x34,0x12,	// mov ecx, 0x12345678 
			0x89,0x01,					// mov [ecx], eax
			0x89,0xec,					// mov esp, ebp
			0x5d,						// pop ebp
			0xc2,0x04,0x00				// ret 4 
		};
		*(DWORD*)&shellcode[7] = (DWORD)loadlibraryaddr;
		*(DWORD*)&shellcode[14] = (DWORD)dllnameaddr;
#endif //defined(_WIN64)
		
		LPVOID shellcodeaddr = (LPVOID)VirtualAllocEx(
			pctx->RemoteHandle,
			NULL,
			sizeof(shellcode) + 0x10,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!shellcodeaddr) {
			printf("alloc fail\n");
			EraseTraces(pctx);
			return FALSE;
		}

		if (!WriteProcessMemory(
			pctx->RemoteHandle,
			dllnameaddr,
			dllname,
			strlen(dllname)+1,
			NULL
		)) {
			printf("ERROR:Can't write in remote process,error code:%d\n", GetLastError());
			EraseTraces(pctx);
			return FALSE;
		}
		if (!WriteProcessMemory(
			pctx->RemoteHandle,
			shellcodeaddr,
			shellcode,
			sizeof(shellcode),
			NULL
		)) {
			printf("ERROR:Can't write in remote process,error code:%d\n", GetLastError());
			EraseTraces(pctx);
			return FALSE;
		}
		
		
		HANDLE hThread = CreateRemoteThread(
			pctx->RemoteHandle,
			NULL,
			0x1000,
			(LPTHREAD_START_ROUTINE)shellcodeaddr,
			dllnameaddr,
			0,
			NULL		
		);

		if (hThread) {
			WaitForSingleObject(hThread, INFINITE);
			DWORD lpExitCode = 0;
			GetExitCodeThread(hThread, &lpExitCode);
			size_t dllbase = 0;
			ReadProcessMemory(
				pctx->RemoteHandle,
				dllnameaddr,
				&dllbase,
				sizeof(size_t),
				NULL
			);
			CloseHandle(hThread);
		}

		pImport++;
	}
                                                                                                                                                                                                  
	return 0;
}

BOOL FixRelocation(PE_CONTEXT* pctx)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pctx->ImageBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("ERROR:IS NOT A PE FILE,WRONG DOS HEADER\n");
		EraseTraces(pctx);
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)
		(pctx->ImageBuffer + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("ERROR:IS NOT A PE FILE,WRONG NT HEADER\n");
		EraseTraces(pctx);
		return FALSE;
	}

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)
		(IMAGE_FIRST_SECTION(pNtHeaders));

	PIMAGE_DATA_DIRECTORY pDataDirectory = 
		(PIMAGE_DATA_DIRECTORY)(&pNtHeaders->OptionalHeader.DataDirectory);
	if (pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0 ||
		pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0) {
		printf("THIS FILE DON'T HAVE RELOCATION\n");
		EraseTraces(pctx);
		return TRUE;
	}

	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(pctx->ImageBuffer + pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (pRelocation->SizeOfBlock != 0) {
		PBYTE lpbaseRe = pctx->RemoteBaseAddress + pRelocation->VirtualAddress;
		PWORD RelocOffset = (PWORD)(((PBYTE)pRelocation) + sizeof(IMAGE_BASE_RELOCATION));

		BYTE type = (*RelocOffset) >> 12;
		WORD offset = (*RelocOffset) & 0xFFF;
		size_t Delta = pctx->RemoteBaseAddress - pctx->ImageBuffer;

		while (*RelocOffset){
			switch (type) {
			case IMAGE_REL_BASED_HIGHLOW: {
				DWORD value = (*(pctx->ImageBuffer + pRelocation->VirtualAddress + offset) + Delta);

				if (!WriteProcessMemory(
					pctx->RemoteHandle,
					lpbaseRe + offset,
					&value,
					sizeof(DWORD),
					NULL
				)) {
					printf("ERROR:can't reloc,offset:%d", offset);
					return FALSE;
				}
				break;
			}
			case IMAGE_REL_BASED_DIR64: {
				ULONGLONG value = (*(pctx->ImageBuffer + pRelocation->VirtualAddress + offset) + Delta);

				if (!WriteProcessMemory(
					pctx->RemoteHandle,
					lpbaseRe + offset,
					&value,
					sizeof(ULONGLONG),
					NULL
				)) {
					printf("ERROR:can't reloc,offset:%d", offset);
					return FALSE;
				}
				break;
			}
			}

			RelocOffset++;
		}

		pRelocation = (PIMAGE_BASE_RELOCATION)((PBYTE)pRelocation + pRelocation->SizeOfBlock);
	}

	return TRUE;
}

BOOL ExcuteDllEntry(PE_CONTEXT* pctx)
{
	return TRUE;
}
