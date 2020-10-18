---
layout: default
title: PE File Structure and Mapping
parent: Posts
---

# **Intro**
---
As incident responders, threat analysts, reverse engineers, etc... process injection into native Windows OS binaries is a typical memory evasion seen in a variety of malware and offensive security tools. By injecting malicious DLLs or shellcode into native remote processes, threat actors can attempt to evade on-disk detections and remain in-memory. Popular offensive security tools such as Cobalt Strike typically inject the Beacon DLL into native binaries such as rundll32.exe through the syswow64 (x86) and sysnative (x64) virtual directory by default. 

Observing rundll32 beaconing to the DigitalOcean ASN may not seem as crazy as 2020 has been but it surely isn't going to make it any better for your organization :). So how can you as an analyst further investigate this suspicious in-memory injected process? A quick understanding of the PE file structures and memory mapping process can help you extract and analyze the injected process on disk.

# **PE File Structure**
---
So what is a PE file and what is the importance of it's structure? The Portable Executable (PE) file format is the Common Object File Format (COFF) for executables (EXE) and Dynamic Link Libraries (DLL) for 32-bit and 64-bit binaries on a Windows operating system. The PE file format contains data structures in order for the Windows loader to interperet and correctly map parts of the file into memory. 

The PE file is broken down into two main sections, the headers and sections. The headers are important data structures for the Windows loader that contain information such as architecture (x86/x64), whether the file is executable, size of each section, preffered virtual base address, etc. We can see an example of a PE file below broken down into the PE headers on the left and different sections on the right:

<img src="{{ site.url }}{{ site.baseurl }}/images/01.png" alt="">
&nbsp;  

The main data structures that we will be taking a look at in regard to file mapping and injected code are the IMAGE_SECTION_HEADERS. For each PE file section in a binary, there is a corresponding IMAGE_SECTION_HEADER structure that contains information such as the location of the section on disk, the size of the section on disk, the virtual address, and virtual size. Below we can see the C++ structure of the IMAGE_SECTION_HEADER:

```
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

```
&nbsp;  

When a PE file is mapped from disk into memory, the Windows loader will allocate the necessary amount of memory the PE file needs and map the sections into memory based on the information specified in the aformentioned structure. It is important to note that the virtual size will typically be smaller than the raw size due to the raw data containing uneccessary data that the file doesn't need. Let's take a look at a 32-bit Internet Explorer (MD5:c613e69c3b191bb02c7a191741a1d024) PE file in PE-Bear:

<img src="{{ site.url }}{{ site.baseurl }}/images/02.png" alt="">
&nbsp;  


Based on the output from PE-Bear, we can see that the raw offset to the .text section (code) is 0x400 and the virtual offset from the base address is 0x1000 in memory. This means that the beginning of the .text section in memory will be at offset 0x1000 relative to the image base in memory. We can also note that the virtual size of the .text section is 0x17b (379 base-10) smaller than the raw size of the section. Let's take a look at where the raw and virtual .text section ends on disk. We can calculate these offsets by adding the raw size to 0x400 as well as the virtual size to 0x400. This calculates to a raw address of 0xA600 (end of raw .text section) and a raw address of 0xA485 (end of virtual .text section):

<img src="{{ site.url }}{{ site.baseurl }}/images/03.png" alt="">
&nbsp; 

The blue highlight indicates where the virtual .text section would end and the red highlight indicates where the raw .text section ends. The virtual offset ends write before the null-byte overlay while the raw .text section includes most of the null-byte overlay indicating a larger size on disk. The notion of memory mapping is important to note when dumping injected PE files from memory (i.e. Beacon DLL). We will dive into this toward the end of this write-up. 

# **Parsing Section Header in C++**
---
While there is already a ton of great write ups on parsing PE files in C++, I wanted to quickly dive into parsing PE headers for those who may be new/learning C++ (a.k.a me) to show some easy examples. Below is example C++ source code that takes a PE file path as an argument, opens a handle to the file, allocates memory from the heap, reads the bytes of the file from disk into the allocated memory, and parses the .text section header:

```
#include <Windows.h>
#include <iostream>

DWORD dBytesRead{ NULL };
PIMAGE_DOS_HEADER dosheader;
PIMAGE_NT_HEADERS ntheader;
PIMAGE_SECTION_HEADER sectionHeader;

LPVOID parseFileHeaders(VOID* heapAddress) {

	dosheader = (PIMAGE_DOS_HEADER)(DWORD)heapAddress;
	ntheader = (PIMAGE_NT_HEADERS)((DWORD)heapAddress + dosheader->e_lfanew);
	DWORD sectionLocation = ((DWORD)ntheader + sizeof(DWORD) + (DWORD)ntheader->FileHeader.SizeOfOptionalHeader + (DWORD)sizeof(IMAGE_FILE_HEADER));
	sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;

	printf("\n========================================================================================================================\n");
	printf("[*] Name of section: %s\n", sectionHeader->Name);
	printf("\n[*] Offset to raw .text section: 0x%x\n", sectionHeader->PointerToRawData);
	printf("\n[*] Size of raw .text section: 0x%x\n", sectionHeader->SizeOfRawData);
	printf("\n[*] Offset to virtual .text section: 0x%x\n", sectionHeader->VirtualAddress);
	printf("\n[*] Size to virtual .text section: 0x%x\n", sectionHeader->Misc.VirtualSize);
	printf("\n========================================================================================================================\n");
	system("pause");
	return NULL;
}

int main(int argc, CHAR* argv[]) {

	HANDLE hInitialFile = CreateFileA(argv[1], 
		GENERIC_ALL, 
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hInitialFile == INVALID_HANDLE_VALUE) {
		printf("Could not read file");
	}

	DWORD dFileSize = GetFileSize(hInitialFile, NULL);

	LPVOID pHeapFile = HeapAlloc(GetProcessHeap(), 0, dFileSize);
	ReadFile(hInitialFile, pHeapFile, dFileSize, &dBytesRead, NULL);

	CloseHandle(hInitialFile);

	parseFileHeaders(pHeapFile);
	

	return NULL;
}
  ```

To calculate the start of the first PE file section, we take the baseaddress of the allocated file in memory and casting it to our PIMAGE_DOS_HEADER struct pointer. From there we calculate the offset to the IMAGE_NT_HEADERS structure by adding the value of e_lfanew to the base address of the file which is typecasted to a DWORD value from the variable **heapAddress**. We can see the format of the IMAGE_NT_HEADERS structure below:

```
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;
  IMAGE_FILE_HEADER       FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

```
In order to get to the start address of the first section we have to add the size of DWORD which is the size of the PE file signature ("PE\0\0") to the start address of the IMAGE_NT_HEADERS structure, add the size of the IMAGE_OPTIONAL_HEADER32 header and the IMAGE_FILE_HEADER structure. The calculation of this offset can be seen by referencing the above PE file format image. After compiling the above C++ source and parsing the 32-bit Internet Explorer binary, we can see that our output matches with the PE-Bear parser:

<img src="{{ site.url }}{{ site.baseurl }}/images/04.png" alt="">

It is also important to note that our Internet Explorer binary is not directly mapped into memory since we read the bytes from disk into an allocated memory buffer. 
