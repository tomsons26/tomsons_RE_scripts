# Unknowns finder
# by tomsons26
#
# Scans though code section of the binary
#	attempting to flag undefined functions it can find,
#	shows a list of things it can't auto flag as functions,
#	shows a list of unknown data that isn't padding
#
#	After making significant fixups press Delete to refresh list
#
#	NOTE script should be retrun after fixes are made if results window is titled "(Maxed out, Fix and Rerun)"
#
# TODO
#	Show a popup window if thats even possible
#	Figure out better masking.. use integer array so mask can be higher than 0xFF?

import ida_kernwin
import idautils
import idc
from ida_kernwin import Choose

chooser = None

# don't take all eternity and don't make a massive list plz
MAX_LOOPS = 50000

#mask to use for byte patterns, TODO probably need better solution
MASK = 0x7F

class MyChoose(Choose):
	def __init__(self):
		Choose.__init__(self, 'Results', [ ["Address", 30], ["Info", 30] ])
		self.n = 0
		self.items = []
		self.n = 0
		self.icon = 5

	def OnInit(self):
		self.items = self.load_items()
		self.n = len(self.items)
		return True

	def OnGetSize(self):
		return len(self.items)

	def OnDeleteLine(self, n):
		self.OnInit()
		# try to preserve the cursor
		if n != 0:
			return (ida_kernwin.Choose.ALL_CHANGED, self.adjust_last_item(n))
		return (ida_kernwin.Choose.ALL_CHANGED, n)

	def OnGetLine(self, n):
		return self.items[n]

	def OnSelectLine(self, n):
		idc.jumpto(int(self.items[n][0], 16))
		return (Choose.NOTHING_CHANGED, )

	def show(self):
		return self.Show(False) >= 0

	CMP_INDEX = 0

	def do_cmp(self, ea, base, data):
		self.CMP_INDEX += 1
		
		test = data
	
		if len(base) != 8 or len(test) != 8:
			print("zero signature %d %d" % (len(base), len(test)))
			return 0
			
		#print('0x%x 11111111\n' % ea)
		#print(' '.join(f'{x:02x}' for x in base))
		#print(' '.join(f'{y:02x}' for y in test))

		#if len(base) != len(test):
		#	print("fix the signature %d %d" % (len(base), len(test)))
		#	return 0
		
		for i in range(len(base)):
			bb = base[i]
			tb = test[i]
			if bb == MASK:
				continue;
			if bb != tb:
				return 0

		return 1
		
	def is_function(self, ea):
		self.CMP_INDEX = 0
		b = get_bytes(ea + 0, 8)
		
		#
		# PROLOGUE TESTS
		#
		# LARGER ONES FIRST

		# sub esp, DWORD; push ebx
		if self.do_cmp(ea, ([0x81, 0xEC, MASK, MASK, MASK, MASK, 0x53, MASK]), b) == 1: return self.CMP_INDEX
		
		# sub esp, DWORD; push esi
		if self.do_cmp(ea, ([0x81, 0xEC, MASK, MASK, MASK, MASK, 0x56, MASK]), b) == 1: return self.CMP_INDEX
		
		# sub esp, BYTE; push ebx
		if self.do_cmp(ea, ([0x81, 0xEC, MASK, 0x53, MASK, MASK, MASK, MASK]), b) == 1: return self.CMP_INDEX

		# sub esp, BYTE; push esi
		if self.do_cmp(ea, ([0x83, 0xEC, MASK, 0x56, MASK, MASK, MASK, MASK]), b) == 1: return self.CMP_INDEX
				
		# sub esp, BYTE; mov, eax DWORD
		if self.do_cmp(ea, ([0x83, 0xEC, MASK, 0xA1, MASK, MASK, MASK, MASK]), b) == 1: return self.CMP_INDEX

		# sub esp, BYTE; mov dl, [esp+44h]
		if self.do_cmp(ea, ([0x83, 0xEC, MASK, 0x8A, MASK, MASK, MASK, MASK]), b) == 1: return self.CMP_INDEX
		
		# sub esp, BYTE; mov eax[esp+X]
		if self.do_cmp(ea, ([0x83, 0xEC, MASK, 0x8B, 0x44, 0x24, MASK, MASK]), b) == 1: return self.CMP_INDEX

		# push sub esp; push ebx
		if self.do_cmp(ea, ([0x83, 0xEC, MASK, 0x53, MASK, MASK, MASK, MASK]), b) == 1: return self.CMP_INDEX

		# push ebp; mov ebp,esp
		if self.do_cmp(ea, ([0x55, 0x8B, 0xEC, MASK, MASK, MASK, MASK, MASK]), b) == 1: return self.CMP_INDEX

		# push esi; mov esi, ecx
		if self.do_cmp(ea, ([0x56, 0x8B, 0xF1, MASK, MASK, MASK, MASK, MASK]), b) == 1: return self.CMP_INDEX
		
		# push ecx; push ebx; push esi
		if self.do_cmp(ea, ([0x51, 0x53, 0x56, MASK, MASK, MASK, MASK, MASK]), b) == 1: return self.CMP_INDEX

		# mov eax, DWORD; call __alloca_probe
		if self.do_cmp(ea, ([0xB8, MASK, MASK, MASK, MASK, 0xE8, MASK, MASK]), b) == 1: return self.CMP_INDEX

		# is alignment before this?
		b = get_bytes(ea - 8, 8)

		#
		# PREVIOUS FUNCTION EPILOGUE TESTS
		#
		# LARGER ONES FIRST

		# BEFORE padding
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0xCC, 0xCC, 0xCC, 0xCC]), b) == 1: return -self.CMP_INDEX
		
		# BEFORE padding
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, MASK, 0xCC, 0xCC, 0xCC]), b) == 1: return -self.CMP_INDEX

		# BEFORE padding
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, MASK, MASK, 0xCC, 0xCC]), b) == 1: return -self.CMP_INDEX

		# BEFORE retn;padding
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, MASK, MASK, 0xC3, 0xCC]), b) == 1: return -self.CMP_INDEX
	
		# BEFORE noppadding
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, MASK, 0x8D, 0x49, 0x00]), b) == 1: return -self.CMP_INDEX

		# BEFORE retn;padding
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0xC3, 0xCC, 0xCC, 0xCC]), b) == 1: return -self.CMP_INDEX
		
		# BEFORE pop ebp;retn
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, MASK, 0x8D, 0x5D, 0xC3]), b) == 1: return -self.CMP_INDEX
		
		# BEFORE mov esp, ebp;pop ebp;retn
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0x8B, 0xE5, 0x5D, 0xC3]), b) == 1: return -self.CMP_INDEX
		
		# BEFORE pop esi;pop ebp;retn
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, MASK, 0x5E, 0x5D, 0xC3]), b) == 1: return -self.CMP_INDEX

		# BEFORE pop esi;pop ebp;retn;padding
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0x5E, 0x5D, 0xC3, 0xCC]), b) == 1: return -self.CMP_INDEX
		
		# BEFORE retn WORD;pop ?
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0x5E, 0xC2, MASK, MASK]), b) == 1: return -self.CMP_INDEX
		
		# BEFORE pop ecx;retn WORD
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0x59, 0xC2, MASK, MASK]), b) == 1: return -self.CMP_INDEX
		
		# BEFORE pop ebp;retn WORD
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0x5D, 0xC2, MASK, MASK]), b) == 1: return -self.CMP_INDEX

		# BEFORE add esp DWORD;retn BYTE
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0x00, 0xC2, MASK, MASK]), b) == 1: return -self.CMP_INDEX

		# BEFORE retn BYTE;padding
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0xC2, MASK, MASK, 0xCC]), b) == 1: return -self.CMP_INDEX

		# BEFORE retn WORD;pop ?
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, MASK, 0xC2, MASK, MASK]), b) == 1: return -self.CMP_INDEX

		# BEFORE pop esi;retn
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, MASK, MASK, 0x5E, 0xC3]), b) == 1: return -self.CMP_INDEX

		# BEFORE add esp, BYTE;retn
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0x83, 0xC4, MASK, 0xC3]), b) == 1: return -self.CMP_INDEX
		
		# BEFORE call DWORD;retn;
		if self.do_cmp(ea, ([MASK, MASK, 0xE8, MASK, MASK, MASK, MASK, 0xC3]), b) == 1: return -self.CMP_INDEX
		
		# BEFORE retn BYTE, padding
		if self.do_cmp(ea, ([MASK, MASK, MASK, 0xC2, MASK, MASK, 0x90, 0x90]), b) == 1: return -self.CMP_INDEX
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0xC2, MASK, MASK, 0x90]), b) == 1: return -self.CMP_INDEX

		# BEFORE retn, padding
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, 0xC3, 0x90, 0x90, 0x90]), b) == 1: return -self.CMP_INDEX
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, MASK, 0xC3, 0x90, 0x90]), b) == 1: return -self.CMP_INDEX
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, MASK, MASK, 0xC3, 0x90]), b) == 1: return -self.CMP_INDEX

		# BEFORE padding
		if self.do_cmp(ea, ([MASK, MASK, MASK, MASK, MASK, 0x90, 0x90, 0x90]), b) == 1: return -self.CMP_INDEX

		return 0
		
	def add_to_list(self, list, min_ea, max_ea, data, search_func, funcs):
		i = 0
		addr = min_ea
		last = -1
		instr = ida_ua.insn_t()
		while addr != BADADDR and i < MAX_LOOPS:
			#addr = ida_bytes.next_unknown(addr, max_ea)
			#addr = ida_bytes.next_that(addr, max_ea, is_smth)
			addr = search_func(addr, idc.SEARCH_DOWN | idc.SEARCH_NEXT)
			if addr >= max_ea:
				break;

			insize = 1
			if last != -1 and ida_ua.decode_insn(instr, last) != 0:
				insize = instr.size
			
			if last == -1 or (last + 1) != addr and last != (addr - insize):
				idx = 0
				if funcs == 1:
					idx = self.is_function(addr)
				if idx != 0:
					ida_funcs.add_func(addr)
					#data1 = str("function found with index %d" % idx)
					#list.append("0x%08X,%s\n" % (addr, data1))
					#i = i + 1
				else:
					list.append("0x%08X,%s\n" % (addr, data))
					i = i + 1
			last = addr
			

		return i >= MAX_LOOPS

	def load_items(self):
		list = []

		min_ea = idc.get_segm_start(ida_ida.inf_get_min_ea())
		max_ea = idc.get_segm_end(ida_ida.inf_get_min_ea())
		
		def is_smth(F):
			#return not ida_bytes.is_code(F) and not ida_bytes.is_tail(F) and not ida_bytes.is_align(F) and ida_bytes.is_data(F) and not ida_bytes.has_xref(F)
			return not ida_bytes.is_align(F) and not ida_bytes.has_xref(F) and ida_bytes.is_data(F)

		maxed_out = 0

		maxed_out = self.add_to_list(list, min_ea, max_ea, "Unknown Data", idc.find_unknown, 0) + maxed_out
		maxed_out = self.add_to_list(list, min_ea, max_ea, "Not Function", idaapi.find_not_func, 1) + maxed_out

		if maxed_out != 0:
			self.title = 'Results (Maxed out, Fix and Rerun)'

		# turn into showable list
		return [line.rstrip().split(',') for line in list]

def gather_unknowns():
	global chooser
	chooser = MyChoose()
	chooser.show()


#if __name__ == '__main__':
#	gather_unknowns()

gather_unknowns()
