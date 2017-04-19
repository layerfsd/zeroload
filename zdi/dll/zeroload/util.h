#pragma once

#include "types.h"
#include "state.h"

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