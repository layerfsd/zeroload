#pragma once

#include "types.h"
#include "hash.h"
#include "parse.h"
#include "peb.h"
#include "state.h"

LPBYTE ZLAPI zl_load_image(PZEROLOAD_STATE pState, LPBYTE lpFileAddr, LPBYTE lpParam, DWORD dwHash);

/**
* @remarks this function probably has relocs, and so isn't called until snapping the IAT (after reloc fixup)
*/
LPBYTE ZLAPI zl_load_read_library_file(PZEROLOAD_STATE pState, const char *szLibrary, LPDWORD dwBytesRead)
{
	DWORD dwLength = 0;
	LPVOID lpBuffer = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	char szFileName[MAX_PATH];// = { 0 };
	szFileName[0] = '\0';

	do
	{
		// todo: search ENV variables too, also doesn't necessarily have to be a .dll
		if (0 == pState->pSearchPathA(NULL, szLibrary, ".dll", sizeof(szFileName), szFileName, NULL))
			break;

		hFile = pState->pCreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, 0);
		if (hFile == INVALID_HANDLE_VALUE)
			break;

		dwLength = pState->pGetFileSize(hFile, NULL);
		if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
			break;

		lpBuffer = pState->pVirtualAlloc(0, dwLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!lpBuffer)
			break;

		if (pState->pReadFile(hFile, lpBuffer, dwLength, dwBytesRead, NULL) == FALSE)
		{
			pState->pVirtualFree(lpBuffer, dwLength, MEM_RELEASE);
			lpBuffer = NULL;
		}
	} while (0);

	if (hFile != INVALID_HANDLE_VALUE)
		pState->pCloseHandle(hFile);

	return (LPBYTE)lpBuffer;
}

BOOL ZLAPI zl_load_import_module(PZEROLOAD_STATE pState, const char *szName, LPBYTE *ppOutDll, BOOL *bAlreadyLoaded)
{
	DWORD dwHash = zl_compute_hash((const void *)szName, 0);
	*bAlreadyLoaded = TRUE;

	// check if its already in the PEB, we will nom it with either strategy
	*ppOutDll = zl_peb_module(dwHash);
	if (*ppOutDll)
		return TRUE;

	// we have two strategies
	if (pState->bReflectAll)
	{
		DWORD dwBytesRead = 0;
		LPBYTE lpFileAddr = NULL;
		PZEROLOAD_DLL pLib = zl_state_dll_find(pState, dwHash);
		
		if (pLib)
		{
			*ppOutDll = pLib->lpBaseAddress;
			return TRUE;
		}

		*bAlreadyLoaded = FALSE;

		lpFileAddr = zl_load_read_library_file(pState, szName, &dwBytesRead);

		if (!lpFileAddr)
			return FALSE;
	
		*ppOutDll = zl_load_image(pState, lpFileAddr, NULL, dwHash);

		pState->pVirtualFree(lpFileAddr, dwBytesRead, MEM_RELEASE);

		if (*ppOutDll)
			return TRUE;
	}
	else
	{
		*bAlreadyLoaded = FALSE;

		*ppOutDll = (LPBYTE)pState->pLoadLibraryA(szName);
		if (*ppOutDll)
			return TRUE;
	}

	return FALSE;
}

void ZLAPI zl_load_sections(LPBYTE lpBaseAddr, LPBYTE lpMapAddr)
{
	PIMAGE_SECTION_HEADER pSection = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = zl_nt_headers(lpBaseAddr);
	WORD wSections = pNtHeaders->FileHeader.NumberOfSections;

	pSection = IMAGE_FIRST_SECTION(pNtHeaders);

	while (wSections--)
	{
		LPBYTE pSectionVA = lpMapAddr + pSection->VirtualAddress;
		LPBYTE pSectionRawData = lpBaseAddr + pSection->PointerToRawData;

		//memcpy(pSectionVA, pSectionRawData, pSection->SizeOfRawData);
		DWORD dwSize = pSection->SizeOfRawData;
		while (dwSize--)
			pSectionVA[dwSize] = pSectionRawData[dwSize];

		++pSection;
	}
}

void ZLAPI zl_load_relocations(LPBYTE lpBaseAddr, LPBYTE lpMapAddr)
{
	LPBYTE lpDelta = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = zl_nt_headers(lpMapAddr);
	PIMAGE_DATA_DIRECTORY pDataDir = zl_data_directory(lpMapAddr, IMAGE_DIRECTORY_ENTRY_BASERELOC);

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
					*(DWORD *)(pBlock + pFirst->offset) += (DWORD)((ULONG_PTR)lpDelta);
				else if (pFirst->type == IMAGE_REL_BASED_HIGH)
					*(WORD *)(pBlock + pFirst->offset) += HIWORD(lpDelta);
				else if (pFirst->type == IMAGE_REL_BASED_LOW)
					*(WORD *)(pBlock + pFirst->offset) += LOWORD(lpDelta);
				// todo: stupid ARM crap

				++pFirst;
			}

			pReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pReloc + pReloc->SizeOfBlock);
		}
	}
}

BOOL ZLAPI zl_load_new_import(PZEROLOAD_STATE pState, PIMAGE_BOUND_IMPORT_DESCRIPTOR *ppBound, PIMAGE_BOUND_IMPORT_DESCRIPTOR pFirst)
{
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBound = NULL;
	char *szBoundImportName = NULL;

	pBound = *ppBound;
	szBoundImportName = (char *)pFirst + pBound->OffsetModuleName;


	return TRUE;
}

BOOL ZLAPI zl_load_new_imports(PZEROLOAD_STATE pState, PIMAGE_BOUND_IMPORT_DESCRIPTOR pBound)
{
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pFirst = pBound;

	while (pBound->OffsetModuleName)
	{
		if (!zl_load_new_import(pState, &pBound, pFirst))
			return FALSE;
	}

	return TRUE;
}

BOOL ZLAPI zl_load_old_import(PZEROLOAD_STATE pState, PIMAGE_IMPORT_DESCRIPTOR *ppImport)
{
	return TRUE;
}

BOOL ZLAPI zl_load_old_imports(PZEROLOAD_STATE pState, PIMAGE_IMPORT_DESCRIPTOR pImport)
{
	while (pImport->Name && pImport->FirstThunk)
	{
		if (!zl_load_old_import(pState, &pImport))
			return FALSE;
	}

	return TRUE;
}

void ZLAPI zl_load_imports(PZEROLOAD_STATE pState, LPBYTE lpBaseAddr, LPBYTE lpMapAddr)
{
}

/**
* @param pState - must be created by zl_state_init(), this function will take ownership and free it
* @param lpFileAddr - base address of read file memory
* @param lpParam - param to send to DllMain
*/
LPBYTE ZLAPI zl_load_image(PZEROLOAD_STATE pState, LPBYTE lpFileAddr, LPBYTE lpParam, DWORD dwHash)
{
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	DWORD dwSize = 0;
	LPBYTE lpMapAddr = NULL;
	
	if (pState == NULL || ++pState->dwDepth > pState->dwMaxDepth)
		return NULL;

	pNtHeaders = zl_nt_headers(lpFileAddr);
	dwSize = pNtHeaders->OptionalHeader.SizeOfImage;

	lpMapAddr = (LPBYTE)pState->pVirtualAlloc(NULL, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (lpMapAddr == NULL)
		return NULL;

	if (pState->bStopPaging)
		pState->pVirtualLock(lpMapAddr, dwSize);

	// copy over headers
	// memcpy((void*)lpMapAddr, (const void*)lpBaseAddr, pNtHeaders->OptionalHeader.SizeOfHeaders);
	while (dwSize--)
		lpMapAddr[dwSize] = lpFileAddr[dwSize];

	// load sections
	zl_load_sections(lpFileAddr, lpMapAddr);

	// fix up relocs
	zl_load_relocations(lpFileAddr, lpMapAddr);	
	
	// add this DLL to state before loading imports, for circular references
	if (!zl_state_dll_add(pState, lpMapAddr, dwSize, dwHash))
		return NULL;

	// load imports, this one can recurse if bReflectAll
	zl_load_imports(pState, lpFileAddr, lpMapAddr);

	// call entry point
	if (pNtHeaders->OptionalHeader.AddressOfEntryPoint != 0x0)
	{
		// lpBaseAddr = &DllMain
		lpFileAddr = lpMapAddr + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
		((FnDllMain_t)lpFileAddr)((HINSTANCE)lpMapAddr, DLL_PROCESS_ATTACH, lpParam);
	}

	if (--pState->dwDepth == 0)
		zl_state_free(pState);

	// lpBaseAddr = &DllMain
	return lpFileAddr;
}