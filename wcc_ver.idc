//
//Watcom Version Checker
//by tomsons26
//Checks Watcom version based on a identified change made in 10.6 to ftell and 10.5A in fclose
//Tested only on NT binaries
#include <idc.idc>

static main() 
{
    auto base;
    base = MinEA();
    
	// seems same for watcall and cdecl?
    // 11.0B change - Input value range checking for strtod() has been improved for very small values.
    //
    // 11.0B strtod chunk
    auto addr11b = FindBinary(base, SEARCH_DOWN, "8B 45 ? 80 E4 7F 25 FF FF 00 00 3D FF 43 00 00 7C 32");
    
    // 10.6 undocumented change
    //
    // 10.6 __wcpp_2_ctor_array__ nullptr check
    auto addr106_1 = FindBinary(base, SEARCH_DOWN, "51 56 57 83 EC 24 89 C1 89 D6 89 DF 85 C0 74 31 89 E2 E8 ? ? ? ? 89 C3 8B 47 01 8B 57 0D 89 44 24 20");
	if (addr106_1 == BADADDR) {
		// cdecl version
		addr106_1 = FindBinary(base, SEARCH_DOWN, "53 56 57 55 83 EC 24 8B 5C 24 38 8B 6C 24 3C 8B 74 24 40 85 DB 74 3B 56 8D 7C 24 04 57 53 E8 ? ? ? ? 89 C7 83 C4 0C 8B 46 01 89 44 24 20");
	}
    
	// TODO cdecl version
   // 10.6 change - The ftell() function could return an incorrect file position for a stream with buffer data for writing and opened for append.
    //
    // 10.6 ftell chunk
    auto addr106_2 = FindBinary(base, SEARCH_DOWN, "F6 42 0C 80 74 0D F6 42 0D 10 74 07");
    
	// TODO cdecl version
    // pre 10.6 ftell chunk
    auto addrp106 = FindBinary(base, SEARCH_DOWN, "F6 42 0D 10 74 05 8D 0C 1E EB 02 29");

    // 11.0A change - Under Windows NT, the C Library now uses VirtualAlloc() and VirtualFree() in place of LocalAlloc() and LocalFree().
    //
    // 10.5A __CreateNewNHeap_ uses VirtualAlloc
    auto addr105a = FindBinary(0, SEARCH_DOWN, "83 3D ? ? ? 00 FE 74 F0 89 E0 E8 ? ? ? ? 85 C0 74 5D 6A 40 68 00 10 00 00 8B 4C 24 08 51 6A 00 E8 ? ? ? ?");
	if (addr105a == BADADDR) {
		// cdecl version
		addr105a = FindBinary(0, SEARCH_DOWN, "83 3D ? ? ? ? ? 74 ? 8D 44 24 ? 50 E8 ? ? ? ? 83 C4 ? 85 C0 74 ? 6A ? 68 ? ? ? ? 8B 4C 24 ? 51 6A ? E8 ? ? ? ?");
	}
 
    // pre 10.5A __CreateNewNHeap_ uses LocalAlloc
    auto addrp105a1 = FindBinary(0, SEARCH_DOWN, "83 3D ? ? ? 00 FE 74 F3 89 E0 E8 ? ? ? ? 85 C0 74 55 8B 0C 24 51 6A 00 E8 ? ? ? ? ");
	if (addrp105a1) {
		// cdecl version
		addrp105a1 = FindBinary(0, SEARCH_DOWN, "83 3D ? ? ? ? ? 74 ? 89 E0 E8 ? ? ? ? 85 C0 74 ? 8B 0C 24 51 6A ? E8 ? ? ? ?");
	}

	// TODO cdecl version
    // pre 10.5A fclose
    auto addrp105a2 = FindBinary(base, SEARCH_DOWN, "53 52 89 C3 FF 15 ? ? ? ? A1 ? ? ? ? 85 C0 75 08 B8 FF FF FF FF 5A 5B C3 3B 58 04 74 04 8B 00 EB EB FF 15 ? ? ? ? BA 01 00 00 00 89 D8 E8 ? ? ? ? 5A 5B C3");

    if (addr11b != BADADDR) {
        Message("Watcom Version Checker - This is a Watcom 11.0B or later binary\n\n");
        return;
    } 
    
    if (addr106_1 != BADADDR) {
        Message("Watcom Version Checker - This is a Watcom 10.6 to Watcom 11.0B(excluding?) binary. Matched __wcpp_2_ctor_array__ signature\n\n");
        return;
    }
   
    if (addr106_2 != BADADDR) {
        Message("Watcom Version Checker - This is a Watcom 10.6 to Watcom 11.0B(excluding?) binary Matched ftell signature\n\n");
        return;
    } 

    if (addrp106 != BADADDR || addrp106 == BADADDR) {
		if (addrp106 == BADADDR) {
			Message("Watcom Version Checker - Warning 10.6 signature not found!\n\n");
		}
        if (addr105a != BADADDR) {
            Message("Watcom Version Checker - This is a Watcom 10.5A binary\n\n");
            return;
        }   
        
        if (addrp105a1 != BADADDR) {
            Message("Watcom Version Checker - This is a Watcom 10.5 or earlier binary. Matched Signature 1\n\n");
            return;
        }   
            
        if (addrp105a2 != BADADDR) {
            Message("Watcom Version Checker - This is a Watcom 10.5 or earlier binary. Matched Signature 2\n\n");
            return;    
        }
        
        Message("Watcom Version Checker - This is pre Watcom 10.6 binary\n\n");
        return;
    }
    
    Message("Watcom Version Checker - Can't indentify compiler version\n\n");

}