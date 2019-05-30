#Imports a file with lines in the form of 0xADDRESS "symbolName"
#Should work both in Ghidra and IDA, at least hasn't broke yet
#@category Data
#@tomsons26 

def Is_IDA():
    return 'IDA_SDK_VERSION' in globals()

def Ask_File():
    if Is_IDA():
        return AskFile(0, "*.symlist", "Select Symbol List file to read")
    else:
        return askFile("Select Symbol List file to read", "Process File")

def Set_Function_Name(address, name):
    if Is_IDA():
        MakeNameEx(int(address, 16), name, False)
    else:
        createLabel(toAddr(long(address, 16)), name, False)

f = Ask_File()

if f:
    if Is_IDA():
        path = f
    else:
        path = f.absolutePath
    
    for line in file(path):
        entry = line.split()
        address = entry[0]
        name = entry[1]
        #print "Creating Symbol", name, "at Address", address
        Set_Function_Name(address, name)
    print "Importing Done\n"