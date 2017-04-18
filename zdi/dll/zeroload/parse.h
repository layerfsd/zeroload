#pragma once

#include "types.h"

/**
@return TRUE if DOS and PE header magic are found in reasonable locations
*/
BOOL ZLAPI zl_valid_pe(LPBYTE lpBaseAddr)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddr;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	if (pDosHeader->e_lfanew <= sizeof(IMAGE_DOS_HEADER))
		return FALSE;

	// note: some PE may fail this test! but not our reflective DLL
	if (pDosHeader->e_lfanew > 1024)
		return FALSE;

	// found MZ and 00PE
	if (((PIMAGE_NT_HEADERS)(lpBaseAddr + pDosHeader->e_lfanew))->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	return TRUE;
}

PIMAGE_NT_HEADERS ZLAPI zl_nt_headers(LPBYTE lpBaseAddr)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddr;
	return (PIMAGE_NT_HEADERS)(lpBaseAddr + pDosHeader->e_lfanew);
}

/**
* @return the IMAGE_NT_OPTIONAL_*_MAGIC
*/
WORD ZLAPI zl_optional_magic(LPBYTE lpBaseAddress)
{
	PIMAGE_NT_HEADERS pNtHeaders = zl_nt_headers(lpBaseAddress);
	WORD wMagic = pNtHeaders->OptionalHeader.Magic;

	return wMagic;
}

PIMAGE_NT_HEADERS32 ZLAPI zl_nt_headers_32(LPBYTE lpBaseAddress)
{
	return (PIMAGE_NT_HEADERS32)zl_nt_headers(lpBaseAddress);
}

PIMAGE_NT_HEADERS64  __forceinline zl_nt_headers_64(LPBYTE lpBaseAddress)
{
	return (PIMAGE_NT_HEADERS64)zl_nt_headers(lpBaseAddress);
}

/**
* @param wIndex - the IMAGE_DIRECTORY_* constant
* @return data directory, or NULL
*/
PIMAGE_DATA_DIRECTORY ZLAPI zl_data_directory(LPBYTE lpBaseAddr, WORD wIndex)
{
	WORD wMagic = zl_optional_magic(lpBaseAddr);
	if (wMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PIMAGE_NT_HEADERS32 pNtHeaders = zl_nt_headers_32(lpBaseAddr);
		return &pNtHeaders->OptionalHeader.DataDirectory[wIndex];
	}
	else if (wMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		PIMAGE_NT_HEADERS64 pNtHeaders = zl_nt_headers_64(lpBaseAddr);
		return &pNtHeaders->OptionalHeader.DataDirectory[wIndex];
	}

	return NULL;
}

/**
@return &IMAGE_NT_HEADERS->FileHeader, or NULL
*/
PIMAGE_FILE_HEADER ZLAPI zl_file_header(LPBYTE lpBaseAddress)
{
	WORD wMagic = zl_optional_magic(lpBaseAddress);

	if (wMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PIMAGE_NT_HEADERS32 pNtHeaders = zl_nt_headers_32(lpBaseAddress);
		return &pNtHeaders->FileHeader;
	}
	else if (wMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		PIMAGE_NT_HEADERS64 pNtHeaders = zl_nt_headers_64(lpBaseAddress);
		return &pNtHeaders->FileHeader;
	}

	return NULL;
}

/**
@param wNumSections - the PIMAGE_NT_HEADERS->FileHeader.NumberOfSections, or -1
@return true if able to find proper headers
*/
BOOL ZLAPI zl_num_sections(LPBYTE lpBaseAddress, LPWORD wNumSections)
{
	WORD wMagic = zl_optional_magic(lpBaseAddress);

	if (wMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PIMAGE_NT_HEADERS32 pNtHeaders = zl_nt_headers_32(lpBaseAddress);
		*wNumSections = pNtHeaders->FileHeader.NumberOfSections;
		return TRUE;
	}
	else if (wMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		PIMAGE_NT_HEADERS64 pNtHeaders = zl_nt_headers_64(lpBaseAddress);
		*wNumSections = pNtHeaders->FileHeader.NumberOfSections;
		return TRUE;
	}

	return FALSE;
}

/**
@return the first section header, if found, else NULL
*/
PIMAGE_SECTION_HEADER ZLAPI zl_first_section(LPBYTE lpBaseAddress)
{
	WORD wMagic = zl_optional_magic(lpBaseAddress);

	if (wMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PIMAGE_NT_HEADERS32 pNtHeaders = zl_nt_headers_32(lpBaseAddress);
		return (PIMAGE_SECTION_HEADER)((LPBYTE)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	}
	else if (wMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		PIMAGE_NT_HEADERS64 pNtHeaders = zl_nt_headers_64(lpBaseAddress);
		return (PIMAGE_SECTION_HEADER)((LPBYTE)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	}

	return NULL;
}

/**
* @return file offset for given virtual address
*/
DWORD ZLAPI zl_rva_offset(LPBYTE lpFileAddress, DWORD dwRva)
{
	WORD wIndex = 0;
	WORD wNumSections = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	pSectionHeader = zl_first_section(lpFileAddress);

	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	if (!zl_num_sections(lpFileAddress, &wNumSections))
		return 0;

	for (wIndex = 0; wIndex < wNumSections; ++wIndex)
	{
		DWORD dwVirtualAddress = pSectionHeader[wIndex].VirtualAddress;
		DWORD dwRawData = pSectionHeader[wIndex].PointerToRawData;

		if (dwRva >= dwVirtualAddress && dwRva < (dwVirtualAddress + dwRawData))
			return (dwRva - dwVirtualAddress + dwRawData);
	}

	return 0;
}

/**
* @return file offset for an export, or 0 if not found
*/
DWORD ZLAPI zl_export_offset(LPBYTE lpFileAddress, const char *szProc)
{
	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	LPDWORD lpNameArray = NULL;
	LPBYTE lpAddressArray = NULL;
	LPWORD lpOrdinalArray = NULL;
	DWORD dwCounter = 0;
	DWORD dwProcHash = 0;

	pDataDir = zl_data_directory(lpFileAddress, IMAGE_DIRECTORY_ENTRY_EXPORT);

	if (pDataDir == NULL)
		return 0;

	pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpFileAddress + zl_rva_offset(lpFileAddress, pDataDir->VirtualAddress));

	lpNameArray = (LPDWORD)(lpFileAddress + zl_rva_offset(lpFileAddress, pExportDir->AddressOfNames));
	lpAddressArray = lpFileAddress + zl_rva_offset(lpFileAddress, pExportDir->AddressOfFunctions);
	lpOrdinalArray = (LPWORD)(lpFileAddress + zl_rva_offset(lpFileAddress, pExportDir->AddressOfNameOrdinals));

	dwCounter = pExportDir->NumberOfNames;
	dwProcHash = zl_compute_hash(szProc, 0);

	while (dwCounter--)
	{
		char *szExport = (char *)(lpFileAddress + zl_rva_offset(lpFileAddress, *(DWORD *)(lpNameArray)));

		if (dwProcHash == zl_compute_hash(szExport, 0))
		{
			lpAddressArray += (*(WORD *)lpOrdinalArray) * sizeof(DWORD);
			return zl_rva_offset(lpFileAddress, *(DWORD *)lpAddressArray);
		}

		++lpNameArray;
		++lpOrdinalArray;
	}

	return 0;
}