#include <stdio.h>
#include <windows.h>

// Converts a relative virtual address (RVA) in memory to a physical address in the file
DWORD RvaToOffset(PIMAGE_SECTION_HEADER sec, int nums, DWORD rva){
    for (int i = 0; i < nums; i++){
        DWORD start = sec[i].VirtualAddress;
        DWORD size = sec[i].SizeOfRawData;

        if (size == 0){
            size = sec[i].Misc.VirtualSize;
        }
        
        if (rva >= start && rva < start + size){
            return ((rva - start) + sec[i].PointerToRawData);
        }
    }
    return 0;
}

// list of the imports function in the Import Address Table (IAT)
void ListarFunc(FILE* f, PIMAGE_SECTION_HEADER Sect, int SecNum, IMAGE_IMPORT_DESCRIPTOR dsc, int ie64){
    DWORD ThunkRva = dsc.OriginalFirstThunk;
    if (ThunkRva == 0) ThunkRva = dsc.FirstThunk;

    DWORD ThunkOffst = RvaToOffset(Sect, SecNum, ThunkRva);
    while(1){
        unsigned __int64 ThunkValue;
        fseek(f, ThunkOffst, SEEK_SET);

        // Check the architecture to determine whether it reads 8-byte (64-bit) or 4-byte (32-bit) blocks
        if (ie64){
            fread(&ThunkValue, 8, 1, f);
            ThunkOffst += 8;
        } else {
            DWORD ie32;
            fread(&ie32, 4, 1, f);
            ThunkValue = ie32;
            ThunkOffst += 4;
        }

        if (ThunkValue == 0) break;
        unsigned __int64 ordinalMask = ie64 ? 0x8000000000000000ULL : 0x80000000;
        unsigned __int64 maskRva = ie64 ? 0x7FFFFFFFFFFFFFFFULL : 0x7FFFFFFF;

        if (ThunkValue & ordinalMask) {
            WORD ord = (WORD)(ThunkValue & 0xFFFF);
            printf("   |-- Ordinal: %u\n", ord);
        } else {
            // Import by name
            DWORD nameRva = (DWORD)(ThunkValue & maskRva);

            DWORD off = RvaToOffset(Sect, SecNum, nameRva);
            if (off == 0) break;

            DWORD OffsetThunkName = off + 2;

            fseek(f, OffsetThunkName, SEEK_SET);

            char FuncName[256] = {0};
            for (int a = 0; a < 255 ; a++){
                int b = fgetc(f);
                if ( b == '\0' || feof(f)) break;

                FuncName[a] = b; 
            }
            printf("   |-- Func: %s\n", FuncName);
        }
    }
}

int main(int argc, char *argv[]){
    if (argc != 2){
        printf("Usage: %s program.exe\n", argv[0]);
        return 1; 
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    // read the DOS Header 
    IMAGE_DOS_HEADER dos;
    fread(&dos,sizeof(dos),1,f);

    if (dos.e_magic != IMAGE_DOS_SIGNATURE){
        printf("Not a valid PE\n");
        fclose(f);
        return 1;
    }

    fseek(f, dos.e_lfanew, SEEK_SET);

    // read the NT signature and NT Header
    DWORD signat;
    IMAGE_FILE_HEADER file;

    fread(&signat, 4, 1,f);
    if (signat != IMAGE_NT_SIGNATURE){
        printf("Not a valid PE");
        fclose(f);
        return 1;
    }
    fread(&file, sizeof(file), 1, f);
    WORD magic;

    fread(&magic, sizeof(WORD), 1, f);
    fseek(f, -2, SEEK_CUR);

    int is64 = (magic == 0x20B);
    DWORD ImportRva;

    // Retrieving the RVA from the imports that in the OP header
    if (is64){
        IMAGE_OPTIONAL_HEADER64 optional;
        fread(&optional, sizeof(optional), 1, f);
        ImportRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else {
        IMAGE_OPTIONAL_HEADER32 optional;
        fread(&optional, file.SizeOfOptionalHeader, 1, f);
        ImportRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }
    fseek(f, dos.e_lfanew + 4 + sizeof(file) + file.SizeOfOptionalHeader, SEEK_SET);

    int numSec = file.NumberOfSections;
    PIMAGE_SECTION_HEADER listSec = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * numSec);

    // map of section table
    for (int i = 0; i < numSec; i++){
        fread(&listSec[i], sizeof(IMAGE_SECTION_HEADER), 1, f);
    }

    DWORD ImportOffset = RvaToOffset(listSec, numSec, ImportRva);

    if (ImportOffset != 0){

        IMAGE_IMPORT_DESCRIPTOR ImportDesc;
        DWORD CurrentImaged = ImportOffset;

        while (1){
            fseek( f, CurrentImaged, SEEK_SET);
            fread(&ImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, f);

            if (ImportDesc.Name == 0) break;

            DWORD Nameoffs = RvaToOffset(listSec, numSec, ImportDesc.Name);
            if (Nameoffs == 0){
                CurrentImaged += sizeof(IMAGE_IMPORT_DESCRIPTOR);
                continue;
            }

            fseek(f, Nameoffs, SEEK_SET);
            char DllName[256] = {0};
            for(int c = 0; c <= 255; c++){
                char n = fgetc(f);
                if (n == '\0' || feof(f)) break;
                DllName[c] = n;
            }
            printf("\n[ Dll: %s ]\n", DllName);

            ListarFunc(f, listSec, numSec, ImportDesc, is64);
            CurrentImaged += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }
    
    free(listSec);
    fclose(f);
    return 0;
}