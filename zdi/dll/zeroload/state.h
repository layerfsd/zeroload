#pragma once

#include "types.h"
#include "hash.h"
#include "peb.h"

PZEROLOAD_DLL ZLAPI zl_state_dll_find(PZEROLOAD_STATE pState, DWORD dwFindHash)
{
	PZEROLOAD_DLL pDll = pState->pLoadedList;

	while (pDll)
	{
		if (pDll->dwHash == dwFindHash)
			return pDll;

		pDll = pDll->pNext;
	}
	
	return NULL;
}

PZEROLOAD_DLL ZLAPI zl_state_dll_add(PZEROLOAD_STATE pState, LPBYTE lpBaseAddr, DWORD dwSize, DWORD dwHash)
{
	PZEROLOAD_DLL pDll = NULL;

	// instead of a linked list, we -could- allocate sizeof(PZEROLOAD_DLL)*dwMaxDepth
	pDll = (PZEROLOAD_DLL)pState->pVirtualAlloc(0, sizeof(PZEROLOAD_DLL), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// O(1) insertion
	pDll->pNext = pState->pLoadedList;
	pState->pLoadedList = pDll;

	pDll->lpBaseAddress = lpBaseAddr;
	pDll->dwSize = dwSize;
	pDll->dwHash = dwHash;

	return pDll;
}

void ZLAPI zl_state_free(PZEROLOAD_STATE pState)
{
	PZEROLOAD_DLL pDll = NULL;

	if (pState == NULL)
		return;

	// free the DLL list
	pDll = pState->pLoadedList;

	while (pDll)
	{
		PZEROLOAD_DLL pTmp = NULL;

		pTmp = pDll->pNext;
		pState->pVirtualFree(pDll, sizeof(PZEROLOAD_DLL), MEM_RELEASE);

		pDll = pTmp;
	}

	// free ourself!
	pState->pVirtualFree(pState, sizeof(PZEROLOAD_STATE), MEM_RELEASE);
}

/**
* @description - builds the state of reflectively loaded DLLs
*
* @return - a state object, or NULL if fail (can no longer fail, see remarks)
*
* @remarks This used error checking before, but it generated a giant jump table (with relocs). anyways,
		   if this fails, the process is in a stupid state and will probably crash soon anyway!
*/
PZEROLOAD_STATE ZLAPI zl_state_init(BOOL bReflectAll, BOOL bStopPaging, DWORD dwMaxDepth)
{
	FnVirtualAlloc_t pVirtualAlloc = NULL;
	PZEROLOAD_STATE pState = NULL;
	LPBYTE lpKernel32 = NULL;
	LPBYTE lpNtDll = NULL;

	// get kernel32.dll and ntdll.dll
	lpKernel32 = zl_peb_module(ZEROLOAD_HASH_KERNEL32);
	lpNtDll = zl_peb_module(ZEROLOAD_HASH_NTDLL);

	pVirtualAlloc = (FnVirtualAlloc_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_VIRTUALALLOC);

	// allocate memory for our state
	pState = (PZEROLOAD_STATE)pVirtualAlloc(0, sizeof(ZEROLOAD_STATE), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	
	pState->pLoadedList = NULL;
	pState->bReflectAll = bReflectAll;
	pState->bStopPaging = bStopPaging;
	pState->dwMaxDepth = dwMaxDepth;
	pState->dwDepth = 0;

	// setup all function pointers
	pState->pVirtualAlloc = pVirtualAlloc;
	pState->pVirtualFree = (FnVirtualFree_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_VIRTUALFREE);
	pState->pNtFlushInstructionCache = (FnNtFlushInstructionCache_t)zl_module_function(lpNtDll, ZEROLOAD_HASH_NTFLUSHINSTRUCTIONCACHE);

	if (pState->bStopPaging)
	{
		pState->pVirtualLock = (FnVirtualLock_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_VIRTUALLOCK);
		pState->pVirtualUnlock = (FnVirtualUnlock_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_VIRTUALUNLOCK);
	}

	if (pState->bReflectAll)
	{
		pState->pSearchPathA = (FnSearchPathA_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_SEARCHPATHA);
		pState->pCreateFileA = (FnCreateFileA_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_CREATEFILEA);
		pState->pGetFileSize = (FnGetFileSize_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_GETFILESIZE);
		pState->pReadFile = (FnReadFile_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_READFILE);
		pState->pCloseHandle = (FnCloseHandle_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_CLOSEHANDLE);
	}
	else
	{
		pState->pLoadLibraryA = (FnLoadLibraryA_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_LOADLIBRARYA);
	}

	return pState;

	/*
	FnVirtualFree_t pVirtualFree = NULL;
	BOOL bDidLoadGood = FALSE;

	if (NULL == (lpKernel32 = zl_peb_module(ZEROLOAD_HASH_KERNEL32)))
		return NULL;

	if (NULL == (lpNtDll = zl_peb_module(ZEROLOAD_HASH_NTDLL)))
		return NULL;

	if (NULL == (pVirtualAlloc = (FnVirtualAlloc_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_VIRTUALALLOC)))
		return NULL;

	if (NULL == (pVirtualFree = (FnVirtualFree_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_VIRTUALFREE)))
		return NULL;

	do
	{
		// things will need to be freed here
		if (NULL == (pState = (PZEROLOAD_STATE)pVirtualAlloc(0, sizeof(ZEROLOAD_STATE), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
			break;

		pState->pVirtualAlloc = pVirtualAlloc;
		pState->pVirtualFree = pVirtualFree;
		pState->pLoadedList = NULL;

		//if (NULL == (pState->pLoadedList = (PZEROLOAD_DLL)pVirtualAlloc(0, sizeof(ZEROLOAD_DLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
			//break;

		if (NULL == (pState->pLoadLibraryA = (FnLoadLibraryA_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_LOADLIBRARYA)))
			break;
	
		if (NULL == (pState->pCreateFileA = (FnCreateFileA_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_CREATEFILEA)))
			break;

		if (NULL == (pState->pGetFileSize = (FnGetFileSize_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_GETFILESIZE)))
			break;

		if (NULL == (pState->pReadFile = (FnReadFile_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_READFILE)))
			break;

		if (NULL == (pState->pCloseHandle = (FnCloseHandle_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_CLOSEHANDLE)))
			break;

		if (NULL == (pState->pSearchPathA = (FnSearchPathA_t)zl_module_function(lpKernel32, ZEROLOAD_HASH_SEARCHPATHA)))
			break;

		if (NULL == (pState->pNtFlushInstructionCache = (FnNtFlushInstructionCache_t)zl_module_function(lpNtDll, ZEROLOAD_HASH_NTFLUSHINSTRUCTIONCACHE)))
			break;

		pState->bReflectAll = ZEROLOAD_REFLECT_ALL;
		pState->dwDepth = 0;
		pState->dwMaxDepth = ZEROLOAD_MAX_DEPTH;

		bDidLoadGood = TRUE;
	}
	while (0);

	if (bDidLoadGood)
		return pState;

	zl_state_free(pState);
		
	return NULL;
	*/
}