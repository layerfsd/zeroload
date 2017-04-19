#pragma once

#include "types.h"
#include "hash.h"
#include "parse.h"
#include "peb.h"
#include "state.h"
#include "util.h"
#include "import.h"

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


/**
* @param pState - must be created by zl_state_init(), this function will take ownership and free it
* @param lpFileAddr - base address of read file memory
* @param lpParam - param to send to DllMain
*/
LPBYTE ZLAPI zl_load_image(PZEROLOAD_STATE pState, LPBYTE lpFileAddr, LPBYTE lpParam, DWORD dwHash)
{
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	DWORD dwSize = 0;
	DWORD dwHeaderSize = 0;
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

	dwHeaderSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
	// copy over headers
	// memcpy((void*)lpMapAddr, (const void*)lpBaseAddr, pNtHeaders->OptionalHeader.SizeOfHeaders);
	while (dwHeaderSize--)
		lpMapAddr[dwHeaderSize] = lpFileAddr[dwHeaderSize];

	// load sections
	zl_load_sections(lpFileAddr, lpMapAddr);

	// fix up relocs
	zl_load_relocations(lpFileAddr, lpMapAddr);	
	
	// add this DLL to state before loading imports, for circular references
	if (!zl_state_dll_add(pState, lpMapAddr, dwSize, dwHash))
		return NULL;

	// load imports, this one can recurse if bReflectAll
	if (!zl_load_imports(pState, lpMapAddr))
		return NULL;

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