# PS2 Lib ID finder
# by tomsons26
#
# Scans though sections of the binary
#	attempting to find PS2 LIB IDs
#	shows a list of found IDs

import ida_kernwin
import idautils
import idc
from ida_kernwin import Choose

chooser = None

def is_print(c):
	return 0x20 <= c <= 0x7E


class MyChoose(Choose):
	def __init__(self):
		Choose.__init__(self, 'PS2 Libraries', [ ["Address", 30], ["Info", 30] ])
		self.items = []
		self.n = 0
		self.icon = 5

	def OnInit(self):
		self.items = self.process()
		return True

	def OnGetSize(self):
		return len(self.items)

	def OnGetLine(self, n):
		return self.items[n]

	def OnSelectLine(self, n):
		idc.jumpto(int(self.items[n][0], 16))
		return (Choose.NOTHING_CHANGED, )

	def show(self):
		return self.Show(False) >= 0

	CURADDRESS = 0x0

	def GetByte(self):
		b = ida_bytes.get_byte(self.CURADDRESS)
		self.CURADDRESS = self.CURADDRESS + 1
		return b

	def TryDecodeID(self, addr):
		decoded = ""

		self.CURADDRESS = addr

		# skip over PsII identifier that we already know matches
		b0 = self.GetByte()
		b1 = self.GetByte()
		b2 = self.GetByte()
		b3 = self.GetByte()

		# while loop lets me keep this easy to read
		while 1:

			# get library name
			name = ""
			for _ in range(8):
				b = self.GetByte()
				# this byte must not be 0xFF and must be printable
				if b == 0xFF or not is_print(b):
					return "FAILED"
				name = name + chr(b)

			# get version number
			ver = ""
			for k in range(4):
				b = self.GetByte()
				# this byte must not be 0xFF
				if b == 0xFF:
					return "FAILED"
				if is_print(b):
					ver = ver + chr(b)
				else:
					ver = ver + str("%x" % chr(b))
				if k <= 2:
					ver = ver + "."

			decoded = decoded + str("%s :\t%s" % (name, ver))

			break


		return decoded
		
	# thanks hexrays
	@staticmethod
	def FindWrapper(binary_pattern, ea):
		if ida_pro.IDA_SDK_VERSION >= 900:
			ea = ida_bytes.find_bytes(binary_pattern, ea, flags=ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW)
		else:
			ea = idc.find_binary(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT | ida_search.SEARCH_NOSHOW, binary_pattern)
			
		return ea

	def process(self):

		found_ea = ida_ida.inf_get_min_ea() - 1
		end_ea = ida_ida.inf_get_max_ea()
		list = []
		
		# letter pattern PsII
		pattern = "50 73 49 49"

		while True:
			found_ea = self.FindWrapper(pattern, found_ea+1)
			if found_ea == idaapi.BADADDR:
				break
			decoded = self.TryDecodeID(found_ea)
			if decoded != "":
				list.append("0x%08X,%s\n" % (found_ea, decoded))
				idc.set_cmt(found_ea, decoded, 0)

		# turn into showable list
		return [line.rstrip().split(',') for line in list]

def gather_info():
	global chooser
	chooser = MyChoose()
	chooser.show()


#if __name__ == '__main__':
#	gather_info()

gather_info()
