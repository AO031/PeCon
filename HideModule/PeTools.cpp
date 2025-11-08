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

	if (!ExcuteDllEntry(pctx)) {
		printf("ERROR:Can't excute dllmain dir\n");
		EraseTraces(pctx);
		return FALSE;
	}

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
			strlen(dllname) + 0x10,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);

		if (!dllnameaddr) {
			printf("alloc fail\n");
			EraseTraces(pctx);
			return FALSE;
		}


#if defined(_WIN64)
		unsigned char LoadShellcode[] = {
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
		*(ULONGLONG*)&LoadShellcode[13] = (ULONGLONG)dllnameaddr;
		*(ULONGLONG*)&LoadShellcode[35] = (ULONGLONG)dllnameaddr;
		*(ULONGLONG*)&LoadShellcode[23] = (ULONGLONG)loadlibraryaddr;
#else
		unsigned char LoadShellcode[] = {
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
		*(DWORD*)&LoadShellcode[7] = (DWORD)loadlibraryaddr;
		*(DWORD*)&LoadShellcode[14] = (DWORD)dllnameaddr;
#endif //defined(_WIN64)
		
		LPVOID LoadShellcodeAddr = (LPVOID)VirtualAllocEx(
			pctx->RemoteHandle,
			NULL,
			sizeof(LoadShellcode) + 0x10,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!LoadShellcodeAddr) {
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
			LoadShellcodeAddr,
			LoadShellcode,
			sizeof(LoadShellcode),
			NULL
		)) {
			printf("ERROR:Can't write in remote process,error code:%d\n", GetLastError());
			EraseTraces(pctx);
			return FALSE;
		}
		
		HANDLE hLoadThread = CreateRemoteThread(
			pctx->RemoteHandle,
			NULL,
			0x1000,
			(LPTHREAD_START_ROUTINE)LoadShellcodeAddr,
			dllnameaddr,
			0,
			NULL		
		);

		size_t dllbaseRe = 0;
		if (hLoadThread) {
			WaitForSingleObject(hLoadThread, INFINITE);
			DWORD lpExitCode = 0;
			GetExitCodeThread(hLoadThread, &lpExitCode);
			if (!ReadProcessMemory(
				pctx->RemoteHandle,
				dllnameaddr,
				&dllbaseRe,
				sizeof(size_t),
				NULL
			)) {
				printf("ERROR:Can't injeck shellcode to get dllbase,dllname:%s\n", dllname);
			}
			CloseHandle(hLoadThread);
			printf("INFO:shellcode get dll base,dll name->%s\n", dllname);
		}

		if (!dllbaseRe) {
			printf("WARRING:Can't injeck shellcode to get dllbase,dllname:%s\n", dllname);
			EraseTraces(pctx);
			pImport++;
			continue; // sometimes there is no dll
		}

		// getprocaddress and fix IAT
		FARPROC getaddr = GetProcAddress(hkernel32, "GetProcAddress");

#if defined(_WIN64)
		unsigned char GetProcShellcode[] = {
			0x50,												// push rax
			0x51,												// push rcx
			0x52,												// push rdx
			0x41,0x50,											// push r8
			0x41,0x51,											// push r9
			0x55,												// push rbp
			0x48,0x89,0xe5,										// mov rbp, rsp
			0x48,0x83,0xec,0x28,								// sub rsp, 0x28
			0x48,0x8b,0x51,0x08,								// mov rdx, [rcx+8]
			0x48,0x8b,0x09,										// mov rcx, [rcx]
			0x48,0xb8,0xf0,0xde,0xbc,0x9a,0x78,0x56,0x34,0x12,	// mov rax, 0x123456789abcdef0 ;getprocaddress
			0xff,0xd0,											// call rax
			0x48,0xb9,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,	// mov rcx, 0x1111111111111111 ;dllname
			0x48,0x89,0x01,										// mov [rcx], rax
			0x48,0x83,0xc4,0x28,								// add rsp, 0x28
			0x48,0x89,0xec,										// mov rsp, rbp
			0x5d,												// pop rbp
			0x41,0x59,											// pop r9
			0x41,0x58,											// pop r8
			0x5a,												// pop rdx
			0x59,												// pop rcx
			0x58,												// pop rax
			0xc3												// ret
		};
		*(ULONGLONG*)&GetProcShellcode[24] = (ULONGLONG)getaddr;
		*(ULONGLONG*)&GetProcShellcode[36] = (ULONGLONG)dllnameaddr;

#else
		unsigned char GetProcShellcode[] = {
			0x55,						// push ebp
			0x89,0xe5,					// mov ebp, esp
			0x8b,0x4d,0x08,				// mov ecx, [ebp+8]
			0xff,0x71,0x04,				// push [ecx+4] ;name or ord
			0xff,0x31,					// push [ecx] ;dllbaseRe
			0xb8,0xff,0xff,0xff,0x7f,	// mov eax, 0x7fffffff ;getprocaddress
			0xff,0xd0,					// call eax
			0xb9,0x78,0x56,0x34,0x12,	// mov ecx, 0x12345678 ;dllnamere
			0x89,0x01,					// mov [ecx], eax
			0x89,0xec,					// mov esp, ebp
			0x5d,						// pop ebp
			0xc2,0x04,0x00				// ret 4 
		};
		*(DWORD*)&GetProcShellcode[12] = (DWORD)getaddr;
		*(DWORD*)&GetProcShellcode[19] = (DWORD)dllnameaddr;
#endif //_WIN64

		PIMAGE_THUNK_DATA pINT = NULL;
		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(pctx->ImageBuffer + pImport->FirstThunk);
		if (pImport->OriginalFirstThunk) {
			pINT = (PIMAGE_THUNK_DATA)(pctx->ImageBuffer + pImport->OriginalFirstThunk);
		}
		else {
			pINT = pIAT;
			continue;
		}
	
		while (pINT->u1.AddressOfData) {
			struct {
				HMODULE dllbase;
				LPCSTR NameOrd;
			} param = {(HMODULE)dllbaseRe,NULL};

			if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.AddressOfData)) {
				param.NameOrd = (LPCSTR)IMAGE_ORDINAL(pINT->u1.AddressOfData);
				printf("\tINFO:FunOrd->%d", IMAGE_ORDINAL(pINT->u1.AddressOfData));
			}
			else {
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pctx->ImageBuffer + pINT->u1.AddressOfData);
				param.NameOrd = (LPCSTR)((size_t)pImportByName->Name + (size_t)pctx->RemoteBaseAddress - (size_t)pctx->ImageBuffer);
				printf("\tINFO:FunName->%s\n", pImportByName->Name);
				// HINT: must be remote
			}
		
			LPVOID ParamAddrRe = (LPVOID)VirtualAllocEx(
				pctx->RemoteHandle,
				NULL,
				sizeof(param),
				MEM_COMMIT | MEM_RESERVE,
				PAGE_READWRITE
			);
			
			if (!ParamAddrRe) {
				printf("ERROR:can't alloc param\n");
				EraseTraces(pctx);
				return FALSE;
			}

			if (!WriteProcessMemory(
				pctx->RemoteHandle,
				ParamAddrRe,
				&param,
				sizeof(param),
				NULL
			)) {
				printf("ERROR:can't write param\n");
				EraseTraces(pctx);
				return FALSE;
			}

			PBYTE GetProcShellcodeAddr = (PBYTE)VirtualAllocEx(
				pctx->RemoteHandle,
				NULL,
				sizeof(GetProcShellcode),
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE
			);
			if (!GetProcShellcodeAddr) {
				printf("ERROR:can't alloc shellcode\n");
				EraseTraces(pctx);
				return FALSE;
			}

			if (!WriteProcessMemory(
				pctx->RemoteHandle,
				GetProcShellcodeAddr,
				&GetProcShellcode,
				sizeof(GetProcShellcode),
				NULL
			)) {
				printf("ERROR:can't write getshellcode\n");
				EraseTraces(pctx);
				return FALSE;
			}

			HANDLE hGetThread = CreateRemoteThread(
				pctx->RemoteHandle,
				NULL,
				0x1000,
				(LPTHREAD_START_ROUTINE)GetProcShellcodeAddr,
				ParamAddrRe,
				0,
				NULL
			);

			size_t FunaddrRe = 0;
			if (hGetThread) {
				WaitForSingleObject(hGetThread, INFINITE);
				DWORD lpExitCode = 0;
				GetExitCodeThread(hGetThread, &lpExitCode);
				if (!ReadProcessMemory(
					pctx->RemoteHandle,
					dllnameaddr,
					&FunaddrRe,
					sizeof(size_t),
					NULL
				)) {
					printf("ERROR:Can't injeck shellcode to get Funaddr\n");
				}
				CloseHandle(hGetThread);
				printf("\tINFO: Remote fun addr->0x%p\n", FunaddrRe);
			}

			if (!WriteProcessMemory(
				pctx->RemoteHandle,
				(LPVOID)((size_t)pIAT + (size_t)pctx->RemoteBaseAddress - (size_t)pctx->ImageBuffer),
				&FunaddrRe,
				sizeof(LPVOID),
				NULL
			)) {
				printf("ERROR:Can't injeck shellcode to get Funaddr");
			}
			printf("\tINFO: fix IAT->0x%p\n", ((size_t)pIAT + (size_t)pctx->RemoteBaseAddress - (size_t)pctx->ImageBuffer));
			printf("\tINFO: fix INT->0x%p\n", ((size_t)pINT + (size_t)pctx->RemoteBaseAddress - (size_t)pctx->ImageBuffer));
			pINT++;
			pIAT++;
		}
		pImport++;
	}
                                                                                                                                                                                                  
	return TRUE;
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
		size_t Delta = (size_t)pctx->RemoteBaseAddress - (size_t)pNtHeaders->OptionalHeader.ImageBase;
		printf("reloc virtual addr:%p\n", pRelocation->VirtualAddress);
		while (*RelocOffset){
			BYTE type = (*RelocOffset) >> 12;
			WORD offset = (*RelocOffset) & 0xFFF;
			

			switch (type) {
			case IMAGE_REL_BASED_HIGHLOW: {
				DWORD oldvalue = *(DWORD*)(pctx->ImageBuffer + pRelocation->VirtualAddress + offset);
				DWORD value = oldvalue + Delta;
				
				printf("\tINFO:Reloca addr->%p,value->%p\n", lpbaseRe + offset, value);
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
				ULONGLONG oldvalue = *(ULONGLONG*)(pctx->ImageBuffer + pRelocation->VirtualAddress + offset);
				ULONGLONG value = oldvalue + Delta;

				printf("INFO:Reloca addr->%p,value->%p\n", lpbaseRe + offset, value);
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
	if (!pctx || pctx->RemoteBaseAddress == 0) {
		printf("ERROR:what param\n");
		return FALSE;
	}

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

	// get entry
	DWORD DllMainEntry = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	if (!DllMainEntry) {
		printf("THIS FILE DON'T HAVE DLLMAIN\n");
		return TRUE;
	}

	// shellcode
#if defined(_WIN64)
	unsigned char shellcode[] = {
		0x51,												// push rcx
		0x52,												// push rdx
		0x41,0x50,											// push r8
		0x41,0x51,											// push r9
		0x55,												// push rbp
		0x48,0x89,0xe5,										// mov rbp, rsp
		0x48,0x83,0xec,0x30,								// sub rsp, 0x30
		0x48,0x8b,0x51,0x08,								// mov rdx, [rcx+8]
		0x48,0x8b,0x09,										// mov rcx, [rcx]
		0x48,0xb8,0xf0,0xde,0xbc,0x9a,0x78,0x56,0x34,0x12,	// mov rax, 0x123456789abcdef0 ;dllmain
		0xff,0xd0,											// call rax
		0x48,0x83,0xc4,0x30,								// add rsp, 0x30
		0x48,0x89,0xec,										// mov rsp, rbp
		0x5d,												// pop rbp
		0x41,0x59,											// pop r9
		0x41,0x58,											// pop r8
		0x5a,												// pop rdx
		0x59,												// pop rcx
		0xc3												// ret
	};
	*(ULONGLONG*)&shellcode[23] = (ULONGLONG)(pctx->RemoteBaseAddress + DllMainEntry);
#else
	unsigned char shellcode[] = {
			0x55,						// push ebp
			0x89,0xe5,					// mov ebp, esp
			0x8b,0x4d,0x08,				// mov ecx, [ebp+8]
			0xff,0x71,0x04,				// push [ecx+4] ;reasonforcall
			0xff,0x31,					// push [ecx] ;remotebase
			0xb8,0xff,0xff,0xff,0x7f,	// mov eax, 0x7fffffff ;dllname
			0xff,0xd0,					// call eax
			0x89,0xec,					// mov esp, ebp
			0x5d,						// pop ebp
			0xc2,0x04,0x00				// ret 4 
	};
	*(DWORD*)&shellcode[12] = (DWORD)(pctx->RemoteBaseAddress+DllMainEntry);
#endif //_WIN64

	LPVOID ShellcodeAddr = VirtualAllocEx(
		pctx->RemoteHandle,
		NULL,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!ShellcodeAddr) {
		printf("ERROR:can't alloc in remote process\n");
		EraseTraces(pctx);
		return FALSE;
	}
	if (!WriteProcessMemory(
		pctx->RemoteHandle,
		ShellcodeAddr,
		&shellcode,
		sizeof(shellcode),
		NULL
	)) {
		printf("ERROR: Can't write shell code\n");
		EraseTraces(pctx);
		return FALSE;
	}

	struct {
		HMODULE hModule;
		size_t reasonforcall;
	} param = {(HMODULE)pctx->RemoteBaseAddress,DLL_PROCESS_ATTACH};


	LPVOID ParamAddr = VirtualAllocEx(
		pctx->RemoteHandle,
		NULL,
		sizeof(param),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (!ParamAddr) {
		printf("ERROR:can't alloc in remote process\n");
		EraseTraces(pctx);
		return FALSE;
	}
	if (!WriteProcessMemory(
		pctx->RemoteHandle,
		ParamAddr,
		&param,
		sizeof(param),
		NULL
	)) {
		printf("ERROR: Can't write shell code\n");
		EraseTraces(pctx);
		return FALSE;
	}


	HANDLE hThread = CreateRemoteThread(
		pctx->RemoteHandle,
		NULL,
		0x1000,
		(LPTHREAD_START_ROUTINE)ShellcodeAddr,
		ParamAddr,
		0,
		NULL
	);
	
	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
		DWORD lpExitCode = 0;
		GetExitCodeThread(hThread, &lpExitCode);
		CloseHandle(hThread);
		printf("EXCUTE SHELLCODE:EXIT CODE:0x%p\n", lpExitCode);
	}

	return TRUE;
}
