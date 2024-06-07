#include <stdio.h>
#include <string.h>
#include <windows.h>

//Function GetFuncCall() to find the Function Address
FARPROC GetFuncCall(HANDLE hKernel32, LPCSTR lpProcName)
{

	DWORD_PTR baseAddress;

	//PE Format Structure Start------------------------------------------------------------------------

	PIMAGE_EXPORT_DIRECTORY ptr_export_directory = NULL;
	PIMAGE_DOS_HEADER ptr_dos_header = NULL;
	PIMAGE_NT_HEADERS64 ptr_nt_header64 = NULL;

	//Base Address;
	baseAddress = (DWORD_PTR)hKernel32;

	//Pointing towards DOS Header
	ptr_dos_header = (PIMAGE_DOS_HEADER)hKernel32;

	if (ptr_dos_header->e_magic != 0x5A4D)
	{
		return 0;
	}

	//Pointing towared NT Headers
	ptr_nt_header64 = (PIMAGE_NT_HEADERS64)(baseAddress + (DWORD_PTR)ptr_dos_header->e_lfanew);
	if (ptr_nt_header64->Signature != 0x4550)
	{
		return 0;
	}

	//Pointing Towards Export Directory
	ptr_export_directory = (PIMAGE_EXPORT_DIRECTORY)(baseAddress + ((DWORD_PTR)ptr_nt_header64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

	//PE Format Structure Ends------------------------------------------------------------------------


	//Retrieving Functions----------------------------------------------------------------------------

	DWORD totalFunctions = ptr_export_directory->NumberOfFunctions;
	DWORD totalNames = ptr_export_directory->NumberOfNames;

	DWORD_PTR nameAddress = baseAddress + ptr_export_directory->AddressOfNames;

	DWORD_PTR ordinalNameAddress = baseAddress + ptr_export_directory->AddressOfNameOrdinals;

	DWORD_PTR functionAddress = baseAddress + ptr_export_directory->AddressOfFunctions;

	WORD ordinalFunc = 0;

	for (DWORD i = 0; i < totalNames; i++)
	{
		LPCSTR funcName = (LPCSTR)(baseAddress + ((DWORD*)nameAddress)[i]);

		if (strcmp(lpProcName, funcName) == 0)
		{
			ordinalFunc = ((WORD*)(ordinalNameAddress))[i];

			break;
		}
	}

	DWORD_PTR addr = baseAddress + ((DWORD*)functionAddress)[ordinalFunc];

	return (FARPROC)addr;
}
