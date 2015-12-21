/*
The MIT License (MIT)

Copyright (c) 2015 Gabriel Corona

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define le32toh(x) x
#define le16toh(x) x
#define htole16(x) x
#else
#include <endian.h>
#endif

struct dos_header {
  uint16_t e_magic;
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_es[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  uint16_t e_lfanew;
};

struct pe_header {
  uint32_t magic;
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};

#define IMAGE_DOS_SIGNATURE            0x5A4D
#define IMAGE_NT_SIGNATURE             0x00004550
#define IMAGE_FILE_MACHINE_I386        0x014c
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020

static
void patch(const char* filename)
{
  FILE* f = fopen(filename, "rw+b");
  if (f == NULL) {
    fprintf(stderr, "Could not open file %s\n", filename);
    exit(1);
  }

  // Read the DOS header:
  struct dos_header dos_header;
  int res = fread(&dos_header, sizeof(dos_header), 1, f);
  if (res != 1) {
    fprintf(stderr, "Could not read DOS header from %s\n", filename);
    exit(1);
  }
  if (le16toh(dos_header.e_magic) != IMAGE_DOS_SIGNATURE) {
    fprintf(stderr, "Bad DOS magic in %s\n", filename);
    exit(1);
  }

  // Read the PE header:
  struct pe_header pe_header;
  if (fseek(f, le16toh(dos_header.e_lfanew), SEEK_SET) == -1
      || fread(&pe_header, sizeof(pe_header), 1, f) != 1 ) {
    fprintf(stderr, "Could not read PE header in %s\n", filename);
    exit(1);
  }
  if (le32toh(pe_header.magic) != IMAGE_NT_SIGNATURE) {
    fprintf(stderr, "Bad PE magic in %s\n", filename);
    exit(1);
  }
  if (le16toh(pe_header.Machine) != IMAGE_FILE_MACHINE_I386) {
    fprintf(stderr, "Not x86 PE file %s\n", filename);
    exit(1);
  }

  // Update the PE header:
  pe_header.Characteristics |= htole16(IMAGE_FILE_LARGE_ADDRESS_AWARE);
  if (fseek(f, le16toh(dos_header.e_lfanew), SEEK_SET) == -1
      || fwrite(&pe_header, sizeof(pe_header), 1, f) != 1 ) {
    fprintf(stderr, "Could not update PE header in %s\n", filename);
    exit(1);
  }
  if (fclose(f) != 0) {
    fprintf(stderr, "Could not close %s\n", filename);
    exit(1);
  }

  return;
}

void help(char* argv0)
{
  fprintf(stderr, "%s - Set the LARGE_ADDRESS_AWARE in PE files.\n\n"
	  "This make 32 bit PE executable able to use more virtual memory.\n"
	  "However, some of them will not work correctly with this flag.\n",
	  argv0
	  );
}

int main(int argc, char** argv)
{
  int no_options = 0;
  for (int i = 1; i < argc; ++i) {
    if (argv[i][0] != '-' || no_options)
      patch(argv[i]);
    else if (strcmp(argv[i], "--help") == 0)
      help(argv[0]);
    else if (strcmp(argv[i], "--") == 0)
      no_options = 1;
    else {
      fprintf(stderr, "Unknown commandline option\n");
      return 1;
    }
  }
  return 0;
}
