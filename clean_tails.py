def remove_tails(addr):
    tail = addr
    
    done = 0
    while ida_funcs.is_func_tail(ida_funcs.get_fchunk(tail)):
        real = FirstFuncFchunk(tail)
        func = idaapi.get_func(real)
        ida_funcs.remove_func_tail(func,tail)
        done = 1
    #if done:
        #ida_funcs.add_func(tail)
    
addr = 0

while True:
    addr = idaapi.find_text(addr, 0, 0, "END OF FUNCTION CHUNK", SEARCH_NEXT|SEARCH_DOWN)
    if addr==BADADDR:
        break
    remove_tails(addr)