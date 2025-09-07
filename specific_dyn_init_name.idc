//
//Dynamic Init Namer written specifically for TS/RA2/YR
//by tomsons26
//

#include <idc.idc>

static Get_Name(addr)
{
    auto function_size = GetFchunkAttr(addr,FUNCATTR_END)-GetFchunkAttr(addr,FUNCATTR_START);

    if (function_size >= 64 + 32) {
        // these are not the static inits you are looking for
        return "";
    }

    auto result = BADADDR;
    auto do_set = 0;

    auto found = 0;
    auto extra = 0;
    auto faddr = 0;
    auto iaddr = 0;

    if (!found) {
        // fld
        result = FindBinary(addr, SEARCH_DOWN, "DD 05");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_math";

            result = FindBinary(addr, SEARCH_DOWN, "DD 05 ? ? ? ? DC 0D ? ? ? ? DD 1D ? ? ? ? C3");
            if (result != BADADDR && result <= addr + function_size) {
                found = 1;
                // fld operand
                faddr = Dword(addr + 2);

                // is deg2rad, need to check on byte level
                if (Byte(faddr + 0) == 0x39
                &&  Byte(faddr + 1) == 0x9D
                &&  Byte(faddr + 2) == 0x52
                &&  Byte(faddr + 3) == 0xA2
                &&  Byte(faddr + 4) == 0x46
                &&  Byte(faddr + 5) == 0xDF
                &&  Byte(faddr + 6) == 0x91
                &&  Byte(faddr + 7) == 0x3F) {

                    MakeName(faddr, "DEG_TO_RAD" + "_" + ltoa(addr, 16));

                    // fmul operand
                    faddr = Dword(addr + 2 + 6);

                    // is 45 degrees
                    if (GetDouble(faddr) == 45.0) {
                        MakeName(faddr, "DEG45" + "_" + ltoa(addr, 16));

                        // fstp operand
                        faddr = Dword(addr + 2 + 6 + 6);
                        MakeName(faddr, "DEG45_AS_RAD" + "_" + ltoa(addr, 16));


                        extra = "_math_deg2rad" + "45";
                    }

                    // is 60 degrees
                    if (GetDouble(faddr) == 60.0) {
                        MakeName(faddr, "DEG60" + "_" + ltoa(addr, 16));

                        // fstp operand
                        faddr = Dword(addr + 2 + 6 + 6);
                        MakeName(faddr, "DEG60_AS_RAD" + "_" + ltoa(addr, 16));


                        extra = "_math_deg2rad" + "60";
                    }

                    // is 90 degrees
                    if (GetDouble(faddr) == 90.0) {
                        MakeName(faddr, "DEG90" + "_" + ltoa(addr, 16));

                        // fstp operand
                        faddr = Dword(addr + 2 + 6 + 6);
                        MakeName(faddr, "DEG90_AS_RAD" + "_" + ltoa(addr, 16));

                        extra = "_math_deg2rad" + "90";
                    }
                }
            } else {
                result = BADADDR;
            }

            if (result == BADADDR) {
                result = FindBinary(addr, SEARCH_DOWN, "DD 05 ? ? ? ? DC 35 ? ? ? ? DD 1D ? ? ? ? C3");
                if (result != BADADDR && result <= addr + function_size) {
                    found = 1;
                    // fld operand
                    faddr = Dword(addr + 2);

                    if (GetDouble(faddr) == 1.0) {
                        extra = "_math_one_div";
                    } else {
                        faddr = Dword(addr + 2 + 6);

                        // is 60 degrees
                        if (GetDouble(faddr) == 60.0) {
                            extra = "_math_div" + "60";
                        }
                    }
                } else {
                    result = BADADDR;
                }
            }

            if (result == BADADDR) {
                result = FindBinary(addr, SEARCH_DOWN, "DD 05 ? ? ? ? DD 05 ? ? ? ? E8 ? ? ? ? DC C0 83 EC 08 DD 1C 24 E8 ? ? ? ? DD 1D ? ? ? ? 83 C4 08 C3");
                if (result != BADADDR && result <= addr + function_size) {
                    found = 1;
                    extra = "_math_pow_sqrt";
                    
                    // fld operand
                    faddr = Dword(addr + 2);

                    if (GetDouble(faddr) == 34.0) {
                        //extra = "_math_pow_sqrt_" + "34";
                        extra = "_math_ISO_TILE_SIZE";
                        
        
                        // mov operand
                        iaddr = Dword((result + 0x1E) + 2);
                        //Message("0x%X\n", iaddr);
                        MakeName(iaddr, "ISO_TILE_SIZE" + "_" + ltoa(addr, 16));
                        
                        
                    } else if (GetDouble(faddr) == 256.0){
                        extra = "_math_CELL_LEPTON_DIAG";
        
                        // mov operand
                        iaddr = Dword((result + 0x1E) + 2);
                        //Message("0x%X\n", iaddr);
                        MakeName(iaddr, "CELL_LEPTON_DIAG" + "_" + ltoa(addr, 16));                        
                    }
                } else {
                    result = BADADDR;
                }
            }

            if (result == BADADDR) {
                result = FindBinary(addr, SEARCH_DOWN, "DD 05 ? ? ? ? DC 25 ? ? ? ? 83 EC 08 DD 1C 24 E8 ? ? ? ? DC 0D ? ? ? ? 83 C4 08 DC 0D ? ? ? ? E8");
                if (result != BADADDR && result <= addr + function_size) {
                    found = 1;
                    //extra = "_math_tan";
                    extra = "_math_LEVEL_LEPTON_H";
                    
                    // mov operand
                    iaddr = Dword((result + 0x2B) + 1);
                    //Message("0x%X\n", iaddr);
                    MakeName(iaddr, "LEVEL_LEPTON_H" + "_" + ltoa(addr, 16));
                } else {
                    result = BADADDR;
                }
            }


            if (result == BADADDR) {
                // only TS
                result = FindBinary(addr, SEARCH_DOWN, "DD 05 ? ? ? ? E8 ? ? ? ? A3 ? ? ? ? C3 ");
                if (result != BADADDR && result <= addr + function_size) {
                    found = 1;
                    extra = "_math_ISO_TILE_PIXEL_W";
        
                    // mov operand
                    iaddr = Dword((result + 0xB) + 1);
                    //Message("0x%X\n", iaddr);
                    MakeName(iaddr, "ISO_TILE_PIXEL_W" + "_" + ltoa(addr, 16));
                } else {
                    result = BADADDR;
                }
            }
        }
    }


    if (!found) {
        // avoid weird edge case with atan_1
        result = FindBinary(addr, SEARCH_DOWN, "A1 ? ? ? ? 99 2B C2 D1 F8 A3 ? ? ? ? C3");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "";
        }

    }

    if (!found) {
        // fild
        result = FindBinary(addr, SEARCH_DOWN, "DB 05");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_math";

            result = FindBinary(addr, SEARCH_DOWN, "DB 05 ? ? ? ? 83 EC 08 DC 0D ? ? ? ? DD 1C 24 E8 ? ? ? ? DD 1D ? ? ? ? 83 C4 08 C3");
            if (result != BADADDR && result <= addr + function_size) {
                found = 1;
                extra = "_math_CELL_SLOPE_ANGLE";
                
                // mov operand
                iaddr = Dword((result + 0x17) + 2);
                //Message("0x%X\n", iaddr);
                MakeName(iaddr, "CELL_SLOPE_ANGLE" + "_" + ltoa(addr, 16));
            } else {
                result = BADADDR;
            }
        }
    }

    if (!found) {
        // fild
        result = FindBinary(addr, SEARCH_DOWN, "DB 44");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_math";
        }
    }

    if (!found) {
        // fmul
        result = FindBinary(addr, SEARCH_DOWN, "DC 0D");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_math";
        }
    }

    if (!found) {
        // cell init
        result = FindBinary(addr, SEARCH_DOWN, "33 C0 66 A3 ? ? ? ? 66 A3 ? ? ? ? C3");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_cell";
        }
    }

    if (!found) {
        // cell init
        result = FindBinary(addr, SEARCH_DOWN, "33 C0 68 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? C6 05 ? ? ? ? ? A2 ? ? ? ? C7 05 ? ? ? ? ? ? ? ? C7 05 ? ? ?");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_dvc";
        }
    }

    if (!found) {
        // coord(0,0,0) init
        result = FindBinary(addr, SEARCH_DOWN, "33 C0 A3 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? C3");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_coord";
        }
    }

    if (!found) {
        // coord(128, 128, 0) init
        result = FindBinary(addr, SEARCH_DOWN, "B8 ? ? ? ? C7 05 ? ? ? ? ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? C3");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_coord";
        }
    }

    if (!found) {
        // rect init
        result = FindBinary(addr, SEARCH_DOWN, "33 C0 A3 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? C3");
        if (result != BADADDR && result <= addr + function_size) {
            found = 1;
            extra = "_rect";
        }
    }

    result = FindBinary(addr, SEARCH_DOWN, "51 A1 ? ? ? ? 83 EC 08 8D 0C 00 89 4C 24 08 DB 44 24 08 DC 35 ? ? ? ? DD 1C 24 E8 ? ? ? ? DD 1D ? ?");
    if (result != BADADDR && result <= addr + function_size) {
        found = 1;
        extra = "_math_CELL_DIAG_SLOPE_ANGLE";
        
        // mov operand
        iaddr = Dword((result + 0x22) + 2);
        //Message("0x%X\n", iaddr);
        MakeName(iaddr, "CELL_DIAG_SLOPE_ANGLE" + "_" + ltoa(addr, 16));
    } else {
        result = BADADDR;
    }

    result = FindBinary(addr, SEARCH_DOWN, "51 A1 ? ? ? ? 8D 0C 85 ? ? ? ? 89 4C 24 00 DB 44 24 00 DC 05 ? ? ? ? E8 ? ? ? ? A3 ? ? ? ? 59 C3");
    if (result != BADADDR && result <= addr + function_size) {
        found = 1;
        extra = "_math_BRIDGE_LEPTON_HEIGHT";
                          
        // mov operand
        iaddr = Dword((result + 0x20) + 1);
        //Message("0x%X\n", iaddr);
        MakeName(iaddr, "BRIDGE_LEPTON_HEIGHT" + "_" + ltoa(addr, 16));
        
    }

    // only TS
    result = FindBinary(addr, SEARCH_DOWN, "A1 ? ? ? ? 8B 0D ? ? ? ? 50 51 E8 ? ? ? ? DC 0D ? ? ? ? 83 C4 08 E8 ? ? ? ? A3 ? ? ? ? C3");
    if (result != BADADDR && result <= addr + function_size) {
        found = 1;
        extra = "_math_ISO_TILE_PIXEL_H";
        
        // mov operand
        iaddr = Dword((result + 0x20) + 1);
        //Message("0x%X\n", iaddr);
        MakeName(iaddr, "ISO_TILE_PIXEL_H" + "_" + ltoa(addr, 16));
    } else {
        result = BADADDR;
    }

    if (found) {
        return "static_init" + extra + "_00" + ltoa(addr, 16);
    }

    //Message("%x was not processed\n", addr);
    return "";
}


static main()
{
    auto addr;

    auto new_name = 0;
    auto parse = 0;
    auto name = 0;

    //!! change segment name if needed
    auto segm = get_segm_by_sel(SegByName(".data"));
    Message("segment at 0x%X\n", segm);

    //is the address valid, does it start with 0 as MSVC dyn init list starts, is it a msvc binary
    if (segm != BADADDR && Dword(segm) == 0 && GetCharPrm(INF_COMPILER) == COMP_MS) {
        // skip over the 0
        addr = segm + 4;
        parse = 1;
    }

    if (parse) {
        auto i = 0;
        while (1) {

            //end of list
            if (Dword(addr) == 0) {
                Message("Reached end of list, marked %d\n", i);
                break;
            }

            if (i == 10000){
                Message("Bugs happened, attempted to process absurd amount\nBaling to prevent inifnite loop\nLast address %X\n", addr);
                break;
            }


            ++i;

            name = Get_Name(Dword(addr));

            if (name != "") {
                //Message("here6\n");
                MakeName(Dword(addr), name);
                //SetColor(Dword(addr), CIC_FUNC, 0xd7d7d7);
                //Message("naming %x, %s\n", Dword(addr), name);
            //} else {
            //    //Message("bailing after %d\n", i);
            //    //break;
            }

            addr = addr + 4;

        }
    } else {
        Message("Can't find dynamic init list or binary not compatible with script!\n");
    }
}