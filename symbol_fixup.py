# run this post class informer to fix rtti and vtable symbols

vtlist = []
rtlist = []
def fixup_name(ea, c):
    nnn = ""
    n = get_name(ea, 0)
    nn = n.split("@@", 1)[0]
   
    if "struct IConnectionPointContainer:" in c:
        nnn = nn + "@@6BIConnectionPointContainer@@@"

    elif "struct IPublicHouse:" in c:
        nnn = nn + "@@6BIPublicHouse@@@"

    elif "struct IHouse:" in c:
        nnn = nn + "@@6BIHouse@@@"

    elif ": struct IStream" in c:
        nnn = nn + "@@6BIStream@@@"
 
    elif "struct ILinkStream:" in c:
        nnn = nn + "@@6BILinkStream@@@"

    elif "IPersistStream" in c:
        nnn = nn + "@@6BIPersistStream@@@"
    
    elif "struct IRTTITypeInfo:" in c:
        nnn = nn + "@@6BIRTTITypeInfo@@@"
    
    elif "struct ILocomotion:" in c:
        nnn = nn + "@@6BILocomotion@@@"
    
    elif "struct IPiggyback:" in c:
        # do nothing
        nnn = nn + "@@6B@"
    
    elif "struct IFlyControl:" in c:
        # do nothing
        nnn = nn + "@@6B@"

    return nnn

def get_new_name(ea):
    c = idaapi.get_extra_cmt(ea - 4, idaapi.E_PREV + 1)
    if c:
        n = fixup_name(ea, c)
        if n != "":
            vtlist.append("0x%X,%s,0,false" % (ea, n))
            ra = Dword(ea - 4)
            r = fixup_name(ra, c)
            if r != "":
                rtlist.append("0x%X,%s,0,false" % (ra, r))
                        
    
def is_candidate(name):
    if "??_7" in name:
        return True
    elif "??_R4" in name:
        return True
    return False
        
for ea, name in idautils.Names():
    if is_candidate(name):
        get_new_name(ea)

print("\n".join(vtlist))
print("\n".join(rtlist))