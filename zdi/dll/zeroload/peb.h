#pragma once

#include "types.h"
#include "hash.h"
#include "parse.h"

PPEB ZLAPI zl_peb()
{
	PPEB pPEB = NULL;

#if defined(_M_AMD64)
	pPEB = (PPEB)__readgsqword(0x60);
#elif defined(_M_IX86)
	pPEB = (PPEB)__readfsdword(0x30);
#elif defined(_M_ARM)
	pPEB = *(DWORD *)((BYTE *)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30); /* CP15_TPIDRURW */
#endif

	return pPEB;
}

PPEB_LDR_DATA ZLAPI zl_peb_ldr()
{
	return zl_peb()->Ldr;
}

/**
@return address of hashed module, if it is in the PEB, else NULL
*/
LPBYTE ZLAPI zl_peb_module(DWORD dwModuleHash)
{
	PPEB_LDR_DATA pLdr = NULL;
	PLIST_ENTRY pList = NULL;
	PLDR_DATA_TABLE_ENTRY pEntry = NULL;

	pLdr = zl_peb_ldr();
	pList = pLdr->InMemoryOrderModuleList.Flink;

	for (; pList; pList = pList->Flink)
	{
		DWORD dwHash = 0;
		pEntry = (PLDR_DATA_TABLE_ENTRY)pList;

		if (pEntry->DllBase == 0x0)
			break;

		dwHash = zl_compute_hash(pEntry->FullDllName.Buffer, pEntry->FullDllName.Length);

		if (dwModuleHash == dwHash)
		{
			pEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			return (LPBYTE)pEntry->DllBase;
		}
	}

	return NULL;
}

FARPROC ZLAPI zl_module_function(LPBYTE lpBaseAddress, DWORD dwProcHash)
{
	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	LPDWORD pNames = NULL;
	LPWORD pOrdinals = NULL;

	pDataDir = zl_data_directory(lpBaseAddress, IMAGE_DIRECTORY_ENTRY_EXPORT);

	if (!pDataDir)
		return NULL;

	pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddress + pDataDir->VirtualAddress);
	pNames = (LPDWORD)(lpBaseAddress + pExportDir->AddressOfNames);
	pOrdinals = (LPWORD)(lpBaseAddress + pExportDir->AddressOfNameOrdinals);

	for (SIZE_T i = 0; i < pExportDir->NumberOfNames; ++i)
	{
		char *szName = (char *)lpBaseAddress + (DWORD_PTR)pNames[i];

		if (zl_compute_hash(szName, 0) == dwProcHash)
			return (FARPROC)(lpBaseAddress + ((DWORD *)(lpBaseAddress + pExportDir->AddressOfFunctions))[pOrdinals[i]]);
	}

	return NULL;
}

FARPROC ZLAPI zl_peb_function(DWORD dwModuleHash, DWORD dwProcHash)
{
	LPBYTE lpBaseAddress = NULL;

	lpBaseAddress = zl_peb_module(dwModuleHash);

	if (!lpBaseAddress)
		return (FARPROC)NULL;

	return zl_module_function(lpBaseAddress, dwProcHash);
}
