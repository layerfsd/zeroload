#pragma once

#include "types.h"
#include "hash.h"
#include "util.h"
#include "peb.h"
#include "state.h"
#include "parse.h"

LPBYTE ZLAPI zl_load_image(PZEROLOAD_STATE pState, LPBYTE lpFileAddr, LPBYTE lpParam, DWORD dwHash);

/**
* @description called during the IAT snapping, checks if DLL is in PEB, if not does the bReflectAll strategy
*
* @remarks todo: trim the beast
*/
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
			*ppOutDll = pLib->lpDllBase;
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

WORD ZLAPI zl_load_name_ordinal(char *szImportName, DWORD dwNumNames, LPBYTE lpExportAddr, LPDWORD pNameTable, LPWORD pOrdinalTable)
{
	// traditionally a binary search would be performed, but we are using hash values;

	WORD dwFound = 0;
	DWORD dwImportHash = zl_compute_hash(szImportName, 0);

	while (dwFound < dwNumNames)
	{
		const char *szTableName = (PCHAR)((ULONG_PTR)lpExportAddr + pNameTable[dwFound]);

		if (zl_compute_hash(szTableName, 0) == dwImportHash)
			return pOrdinalTable[dwFound];

		++dwFound;
	}

	return -1;
}

BOOL ZLAPI zl_load_snap_thunk(PZEROLOAD_STATE pState, LPBYTE lpExportAddr, LPBYTE lpImportAddr, PIMAGE_THUNK_DATA pOriginalThunk,
	PIMAGE_THUNK_DATA pFirstThunk, PIMAGE_EXPORT_DIRECTORY pExportEntry, char *szDllName)
{
	DWORD dwOriginalOrdinal = 0;
	WORD wOrdinal = 0;
	BOOL bIsOrdinal = FALSE;
	PIMAGE_IMPORT_BY_NAME pAddressOfData = NULL;
	LPDWORD pNameTable = NULL;
	LPWORD pOrdinalTable = NULL;
	char *szImportName = NULL;
	PULONG pAddressOfFunctions = NULL;

	if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
	{
		bIsOrdinal = TRUE;
		dwOriginalOrdinal = IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal);
		wOrdinal = (WORD)(dwOriginalOrdinal - (pExportEntry->Base));
	}
	else
	{
		pAddressOfData = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)lpImportAddr + (pOriginalThunk->u1.AddressOfData & 0xFFFFFFFF));
		szImportName = (char *)pAddressOfData->Name;
		pNameTable = (LPDWORD)((ULONG_PTR)lpExportAddr + (ULONG_PTR)pExportEntry->AddressOfNames);
		pOrdinalTable = (LPWORD)((ULONG_PTR)lpExportAddr + (ULONG_PTR)pExportEntry->AddressOfNameOrdinals);

		wOrdinal = zl_load_name_ordinal(szImportName, pExportEntry->NumberOfFunctions, lpExportAddr, pNameTable, pOrdinalTable);
	}

	if ((ULONG)wOrdinal >= pExportEntry->NumberOfFunctions)
		return FALSE;

	pAddressOfFunctions = (PULONG)((ULONG_PTR)lpExportAddr + (ULONG_PTR)pExportEntry->AddressOfFunctions);

	pFirstThunk->u1.Function = (ULONG_PTR)lpExportAddr + pAddressOfFunctions[wOrdinal];

	return TRUE;
}

BOOL ZLAPI zl_load_snap_iat(PZEROLOAD_STATE pState, LPBYTE lpExportAddr, LPBYTE lpImportAddr, PIMAGE_IMPORT_DESCRIPTOR pIatEntry)
{
	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	LPVOID pIAT = NULL;

	pNtHeaders = zl_nt_headers(lpImportAddr);

	if (!pNtHeaders)
		return FALSE;

	pExportDir = (PIMAGE_EXPORT_DIRECTORY)zl_data_directory_virtual_address(lpExportAddr, IMAGE_DIRECTORY_ENTRY_EXPORT);

	if (!pExportDir)
		return FALSE;

	pIAT = (LPVOID)zl_data_directory(lpImportAddr, IMAGE_DIRECTORY_ENTRY_IAT);

	if (!pIAT)
	{
		PIMAGE_SECTION_HEADER pSectionHeader = NULL;
		DWORD dwRva = 0;

		pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

		dwRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

		if (dwRva)
		{
			WORD wIndex = 0;
			for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
			{
				if ((dwRva >= pSectionHeader->VirtualAddress) &&
					(dwRva < (pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)))
					pIAT = (PVOID)((ULONG_PTR)(lpImportAddr)+pSectionHeader->VirtualAddress);
			}
		}

		if (!pIAT)
			return FALSE;
	}


#if 0
	{
		char *szImportName = (LPSTR)((ULONG_PTR)lpImportAddr + pIatEntry->Name);
		DWORD dwForwarderChain = pIatEntry->ForwarderChain;

		while (dwForwarderChain != -1)
		{
			PIMAGE_THUNK_DATA pFirstThunk = NULL, pOriginalThunk = NULL;
			pOriginalThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpImportAddr + pIatEntry->OriginalFirstThunk + (dwForwarderChain * sizeof(IMAGE_THUNK_DATA)));
			pFirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpImportAddr + pIatEntry->FirstThunk + (dwForwarderChain * sizeof(IMAGE_THUNK_DATA)));

			dwForwarderChain = pFirstThunk->u1.Ordinal;

			if (!zl_load_snap_thunk(pState, lpExportAddr, lpImportAddr, pOriginalThunk, pFirstThunk, pExportDir, szImportName))
				return FALSE;
		}
	}
#endif

	if (pIatEntry->FirstThunk)
	{
		PIMAGE_THUNK_DATA pFirstThunk = NULL, pOriginalThunk = NULL;
		char *szImportName = NULL;

		pFirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpImportAddr + pIatEntry->FirstThunk);

		if (pIatEntry->Characteristics < pNtHeaders->OptionalHeader.SizeOfHeaders ||
			pIatEntry->Characteristics >= pNtHeaders->OptionalHeader.SizeOfImage)
		{
			pOriginalThunk = pFirstThunk;
		}
		else
		{
			pOriginalThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpImportAddr + pIatEntry->OriginalFirstThunk);
		}

		szImportName = (LPSTR)((ULONG_PTR)lpImportAddr + pIatEntry->Name);
		while (pOriginalThunk->u1.AddressOfData)
		{
			if (!zl_load_snap_thunk(pState, lpExportAddr, lpImportAddr, pOriginalThunk, pFirstThunk, pExportDir, szImportName))
				return FALSE;

			++pFirstThunk;
			++pOriginalThunk;
		}
	}

	return TRUE;
}

BOOL ZLAPI zl_load_new_import(PZEROLOAD_STATE pState, LPBYTE lpBaseAddr, PIMAGE_BOUND_IMPORT_DESCRIPTOR *ppBound, PIMAGE_BOUND_IMPORT_DESCRIPTOR pFirst)
{
	BOOL bIsAlreadyLoaded = FALSE;
	LPBYTE pDllBaseAddr = NULL;
	PIMAGE_BOUND_FORWARDER_REF pForwarderRef = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBound = NULL;
	char *szBoundImportName = NULL;
	char *szForwarderName = NULL;
	WORD wRefIndex = 0;

	pBound = *ppBound;
	szBoundImportName = (char *)pFirst + pBound->OffsetModuleName;

	if (!zl_load_import_module(pState, szBoundImportName, &pDllBaseAddr, &bIsAlreadyLoaded))
		return FALSE;

	pForwarderRef = (PIMAGE_BOUND_FORWARDER_REF)(pBound + 1);

	for (wRefIndex = 0; wRefIndex < pBound->NumberOfModuleForwarderRefs; ++wRefIndex)
	{
		LPBYTE lpForwardAddr = NULL;
		szForwarderName = (char *)pFirst + pForwarderRef->OffsetModuleName;

		if (!zl_load_import_module(pState, szForwarderName, &lpForwardAddr, &bIsAlreadyLoaded))
			return FALSE;

		++pForwarderRef;
	}

	pFirst = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)pForwarderRef;

	// we don't check for stale entries, just assume they are stale

	PIMAGE_DATA_DIRECTORY pImportDir = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportEntry = NULL;

	pImportDir = zl_data_directory(lpBaseAddr, IMAGE_DIRECTORY_ENTRY_IMPORT);
	pImportEntry = (PIMAGE_IMPORT_DESCRIPTOR)(lpBaseAddr + pImportDir->VirtualAddress);

	while (pImportEntry->Name)
	{
		char *szImportName = ((LPSTR)((ULONG_PTR)lpBaseAddr + pImportEntry->Name));
		if (zl_compute_hash(szImportName, 0) == zl_compute_hash(szBoundImportName, 0))
			break;

		++pImportEntry;
	}

	if (!pImportEntry->Name)
		return FALSE;

	if (!zl_load_snap_iat(pState, pDllBaseAddr, lpBaseAddr, pImportEntry))
		return FALSE;

	return TRUE;
}

BOOL ZLAPI zl_load_new_imports(PZEROLOAD_STATE pState, LPBYTE lpBaseAddr, PIMAGE_BOUND_IMPORT_DESCRIPTOR pBound)
{
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pFirst = pBound;

	while (pBound->OffsetModuleName)
	{
		if (!zl_load_new_import(pState, lpBaseAddr, &pBound, pFirst))
			return FALSE;
	}

	return TRUE;
}

BOOL ZLAPI zl_load_old_import(PZEROLOAD_STATE pState, LPBYTE lpBaseAddr, PIMAGE_IMPORT_DESCRIPTOR *ppImportEntry)
{
	LPBYTE lpExportDll = NULL;
	BOOL bAlreadyLoaded = FALSE;
	PIMAGE_THUNK_DATA pFirstThunk = NULL;
	char *szImportName = (LPSTR)((ULONG_PTR)lpBaseAddr + (*ppImportEntry)->Name);

	pFirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpBaseAddr + (*ppImportEntry)->FirstThunk);

	// what? no function lol
	if (!pFirstThunk->u1.Function)
	{
		++(*ppImportEntry);
		return TRUE;
	}

	if (!zl_load_import_module(pState, szImportName, &lpExportDll, &bAlreadyLoaded))
		return FALSE;

	if (!zl_load_snap_iat(pState, lpExportDll, lpBaseAddr, *ppImportEntry))
		return FALSE;

	++(*ppImportEntry);

	return TRUE;
}

BOOL ZLAPI zl_load_old_imports(PZEROLOAD_STATE pState, LPBYTE lpBaseAddr, PIMAGE_IMPORT_DESCRIPTOR pImport)
{
	while (pImport->Name && pImport->FirstThunk)
	{
		if (!zl_load_old_import(pState, lpBaseAddr, &pImport))
			return FALSE;
	}

	return TRUE;
}

BOOL ZLAPI zl_load_imports(PZEROLOAD_STATE pState, LPBYTE lpMapAddr)
{
	PIMAGE_IMPORT_DESCRIPTOR pImport = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBound = NULL;

	// try new bound imports
	pBound = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)zl_data_directory_virtual_address(lpMapAddr, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);

	if (pBound)
		return zl_load_new_imports(pState, lpMapAddr, pBound);

	// walk old import
	pImport = (PIMAGE_IMPORT_DESCRIPTOR)zl_data_directory_virtual_address(lpMapAddr, IMAGE_DIRECTORY_ENTRY_IMPORT);

	if (pImport)
		return zl_load_old_imports(pState, lpMapAddr, pImport);

	return FALSE;
}