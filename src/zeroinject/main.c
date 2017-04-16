#include "../zeroload/zeroload.h"

PPEB_LDR_DATA __forceinline zeroload_get_peb_ldr()
{
	PPEB lpPEB;

#if defined(_M_AMD64)
	lpPEB = (PPEB)__readgsqword(0x60);
#elif defined(_M_IX86)
	lpPEB = (PPEB)__readfsdword(0x30);
#elif defined(_M_ARM)
	lpPEB = *(DWORD *)((BYTE *)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30); /* CP15_TPIDRURW */
#endif

	return lpPEB->Ldr;
}

PIMAGE_NT_HEADERS __forceinline zeroload_get_nt_headers(LPBYTE lpBaseAddr)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddr;
	return (PIMAGE_NT_HEADERS)(lpBaseAddr + pDosHeader->e_lfanew);
}

PIMAGE_EXPORT_DIRECTORY __forceinline zeroload_get_export_dir(LPBYTE lpBaseAddr)
{
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_DATA_DIRECTORY pDataDir = NULL;

	pNtHeaders = zeroload_get_nt_headers(lpBaseAddr);
	pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	return (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddr + pDataDir->VirtualAddress);
}

PIMAGE_IMPORT_DESCRIPTOR __forceinline zeroload_get_import_descriptor(LPBYTE lpBaseAddr)
{
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_DATA_DIRECTORY pDataDir = NULL;

	pNtHeaders = zeroload_get_nt_headers(lpBaseAddr);

	pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	return (PIMAGE_IMPORT_DESCRIPTOR)(lpBaseAddr + pDataDir->VirtualAddress);
}

// this is a variation of the fnv1a_32 hash algorithm, but keeping the original primes,
// changed to allow both unicode and char*, slower but same distribution for ascii text
DWORD __forceinline zeroload_compute_hash(const void *input, DWORD len)
{
	const unsigned char *data = input;
	
	DWORD hash = 2166136261;
	
	while (1)
	{
		char current = *data;
		if (len == 0)
		{
			if (*data == 0)
				break;
		}
		else
		{
			if ((data - (const unsigned char *)input) >= len)
				break;

			if (*data == 0)
			{
				++data;
				continue;
			}
		}

		// toupper
		if (current >= 'a')
			current -= 0x20;

		hash ^= current;
		hash *= 16777619;
		
		++data;
	}

	return hash;
}

FARPROC __forceinline zeroload_get_proc_addr_hash(LPBYTE lpBaseAddress, DWORD dwProcHash)
{
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	LPDWORD pNames = NULL;
	LPWORD pOrdinals = NULL;

	pExportDir = zeroload_get_export_dir(lpBaseAddress);

	pNames = (LPDWORD)(lpBaseAddress + pExportDir->AddressOfNames);
	pOrdinals = (LPWORD)(lpBaseAddress + pExportDir->AddressOfNameOrdinals);

	for (SIZE_T i = 0; i < pExportDir->NumberOfNames; ++i)
	{
		char *szName = lpBaseAddress + (DWORD_PTR)pNames[i];

		if (zeroload_compute_hash(szName, 0) == dwProcHash)
			return (FARPROC)(lpBaseAddress + ((DWORD *)(lpBaseAddress + pExportDir->AddressOfFunctions))[pOrdinals[i]]);
	}

	return NULL;
}

FARPROC __forceinline zeroload_get_proc_addr(LPBYTE lpBaseAddress, const char *proc)
{
	//if (((DWORD_PTR)proc >> 16) == 0)
		// this is an ordinal

	return zeroload_get_proc_addr_hash(lpBaseAddress, zeroload_compute_hash(proc, 0));
}


LPBYTE __forceinline zeroload_get_module_hash(DWORD dwModuleHash)
{
	PPEB_LDR_DATA pLdr = NULL;
	PLIST_ENTRY pList = NULL;
	PLDR_DATA_TABLE_ENTRY pEntry = NULL;

	pLdr = zeroload_get_peb_ldr();
	pList = pLdr->InMemoryOrderModuleList.Flink;

	for (; pList; pList = pList->Flink)
	{
		DWORD dwHash = 0;
		pEntry = (PLDR_DATA_TABLE_ENTRY)pList;

		if (pEntry->DllBase == 0x0)
			break;

		dwHash = zeroload_compute_hash(pEntry->FullDllName.Buffer, pEntry->FullDllName.Length);

		if (dwModuleHash == dwHash)
		{
			pEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			return (LPBYTE)pEntry->DllBase;
		}
	}

	return NULL;
}

LPBYTE __forceinline zeroload_get_module(PUNICODE_STRING name)
{
	return zeroload_get_module_hash(zeroload_compute_hash(name->Buffer, name->Length));
}

FARPROC __forceinline zeroload_resolve_function_hash(DWORD dwModuleHash, DWORD dwProcHash)
{
	LPBYTE lpBaseAddr = zeroload_get_module_hash(dwModuleHash);

	if (!lpBaseAddr)
		return NULL;

	return zeroload_get_proc_addr_hash(lpBaseAddr, dwProcHash);
}

VOID __forceinline zeroload_load_sections(LPBYTE lpBaseAddr, LPBYTE lpMapAddr)
{
	PIMAGE_NT_HEADERS pNtHeaders = zeroload_get_nt_headers(lpBaseAddr);
	PIMAGE_SECTION_HEADER pSection = NULL;
	WORD wSections = pNtHeaders->FileHeader.NumberOfSections;

	pSection = IMAGE_FIRST_SECTION(pNtHeaders);

	while (wSections--)
	{
		LPBYTE pSectionVA = lpMapAddr + pSection->VirtualAddress;
		LPBYTE pSectionRawData = lpBaseAddr + pSection->PointerToRawData;

		memcpy(pSectionVA, pSectionRawData, pSection->SizeOfRawData);

		++pSection;
	}
}

VOID __forceinline zeroload_load_library()
{

}

VOID __forceinline zeroload_load_imports(LPBYTE lpBaseAddr, LPBYTE lpMapAddr)
{
	PIMAGE_IMPORT_DESCRIPTOR pImport = NULL;

	pImport = zeroload_get_import_descriptor(lpMapAddr);

	while (pImport->Name)
	{
		if (pImport->ForwarderChain != 0)
		{
			// todo: setup forwarders;
			++pImport;
			continue;
		}

		const char *szLibName = lpMapAddr + pImport->Name;
		DWORD dwHash = zeroload_compute_hash(szLibName, 0);
		LPBYTE lpLibrary = zeroload_get_module_hash(dwHash);

		if (!lpLibrary)
		{
			LPBYTE addr = zeroload_read_library_file(szLibName);
			if (addr)
				lpLibrary = zeroload_load_image(addr);
		}

		if (lpLibrary)
		{
			PIMAGE_THUNK_DATA lpOrginalThunk = (PIMAGE_THUNK_DATA)(lpMapAddr + pImport->OriginalFirstThunk);
			ULONG_PTR *lpIAT = (ULONG_PTR *)(lpMapAddr + pImport->FirstThunk);

			while (*(ULONG_PTR *)lpIAT)
			{
				if (lpOrginalThunk && lpOrginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)(lpMapAddr + *lpIAT);
					*lpIAT = (ULONG_PTR)zeroload_get_proc_addr(lpLibrary, pByName->Name);
				}
				
				++lpIAT;
				if (lpOrginalThunk)
					++lpOrginalThunk;
			}
		}

		++pImport;
	}
}

PIMAGE_DATA_DIRECTORY __forceinline zeroload_get_data_dir(LPBYTE lpBaseAddr, SIZE_T nIndex)
{
	return &(zeroload_get_nt_headers(lpBaseAddr)->OptionalHeader.DataDirectory[nIndex]);
}

VOID __forceinline zeroload_load_relocations(LPBYTE lpBaseAddr, LPBYTE lpMapAddr)
{
	LPBYTE lpDelta = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = zeroload_get_nt_headers(lpMapAddr);
	PIMAGE_DATA_DIRECTORY pDataDir = zeroload_get_data_dir(lpMapAddr, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	lpDelta = lpMapAddr - pNtHeaders->OptionalHeader.ImageBase;

	if (pDataDir->Size)
	{
		PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(lpMapAddr + pDataDir->VirtualAddress);

		while (pReloc->SizeOfBlock)
		{
			LPBYTE pBlock = lpMapAddr + pReloc->VirtualAddress;
			DWORD dwNumEntries = pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(ZEROLOAD_IMAGE_RELOC);
			PZEROLOAD_IMAGE_RELOC pFirst = (PZEROLOAD_IMAGE_RELOC)(pReloc + 1);

			while (dwNumEntries--)
			{
				if (pFirst->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR *)(pBlock + pFirst->offset) += (ULONG_PTR)lpDelta;
				else if (pFirst->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD *)(pBlock + pFirst->offset) += (DWORD)lpDelta;
				else if (pFirst->type == IMAGE_REL_BASED_HIGH)
					*(WORD *)(pBlock + pFirst->offset) += HIWORD(lpDelta);
				else if (pFirst->type == IMAGE_REL_BASED_LOW)
					*(WORD *)(pBlock + pFirst->offset) += LOWORD(lpDelta);

				++pFirst;
			}

			pReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pReloc + pReloc->SizeOfBlock);
		}
	}


}


LPBYTE __forceinline zeroload_load_image(LPBYTE lpBaseAddr)
{
	FnVirtualAlloc_t pVirtualAlloc = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	LPBYTE lpMapAddr = NULL;
	SIZE_T i = 0;

	pNtHeaders = zeroload_get_nt_headers(lpBaseAddr);

	pVirtualAlloc = (FnVirtualAlloc_t)zeroload_resolve_function_hash(ZEROLOAD_HASH_KERNEL32, ZEROLOAD_HASH_VIRTUALALLOC);
	
	lpMapAddr = pVirtualAlloc(NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// copy over headers
	memcpy((void*)lpMapAddr, (const void*)lpBaseAddr, pNtHeaders->OptionalHeader.SizeOfHeaders);

	// load sections
	zeroload_load_sections(lpBaseAddr, lpMapAddr);

	// process imports
	zeroload_load_imports(lpBaseAddr, lpMapAddr);

	// process relocs
	zeroload_load_relocations(lpBaseAddr, lpMapAddr);

	// call entry point
	if (pNtHeaders->OptionalHeader.AddressOfEntryPoint != 0x0)
	{
		lpBaseAddr = lpMapAddr + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
		((FnDllMain_t)lpBaseAddr)((HINSTANCE)lpMapAddr, DLL_PROCESS_ATTACH, NULL);
	}
	return lpMapAddr;
}

LPBYTE zeroload_read_library_file(const char *szLibrary)
{
	DWORD dwLength = 0;
	DWORD dwBytesRead = 0;
	LPVOID lpBuffer = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	char szFileName[MAX_PATH] = { 0 };

	do
	{
		// todo: search ENV variables too
		if (0 == SearchPathA(NULL, szLibrary, ".dll", sizeof(szFileName), szFileName, NULL))
			break;

		hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, 0);
		if (hFile == INVALID_HANDLE_VALUE)
			break;

		dwLength = GetFileSize(hFile, NULL);
		if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
			break;

		lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
		if (!lpBuffer)
			break;

		if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
		{
			HeapFree(GetProcessHeap(), 0, lpBuffer);
			lpBuffer = NULL;
		}
	} while (0);

	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	return (LPBYTE)lpBuffer;
}

#include <stdio.h>
#include <stdlib.h>

void test_get_proc_addr(const char *szModule, const char *szProc)
{
	LPBYTE pModule = zeroload_get_module_hash(ZEROLOAD_HASH_KERNEL32);
	printf("%s::%s = 0x%08x\n", szModule, szProc, zeroload_compute_hash(szProc, 0));
	printf("%llx::%llx\n", (DWORD64)pModule, (DWORD64)zeroload_get_proc_addr(pModule, szProc));
	printf("%llx::%llx\n", (DWORD64)GetModuleHandleA(szModule), (DWORD64)GetProcAddress(GetModuleHandleA(szModule), szProc));
	printf("\n");
}

int main()
{
	//LoadLibraryA("user32.dll");
	LPBYTE addr = zeroload_read_library_file("zeroload");
	zeroload_load_image(addr);

	//LoadLibraryA("zeroload.dll");

	//printf("%llx\n", addr);


	printf("%08x\n", zeroload_compute_hash("ntdll.dll", 0));

	test_get_proc_addr("kernel32.dll", "LoadLibraryA");
	test_get_proc_addr("kernel32.dll", "VirtualAlloc");

	system("PAUSE");
	return 0;
}