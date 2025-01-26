# PSX Lib ID finder
# by tomsons26
#
# Scans though code section of the binary
#	attempting to find PSX LIB IDs
#	shows a list of found IDs

import ida_kernwin
import idautils
import idc
from ida_kernwin import Choose

chooser = None

class MyChoose(Choose):
	def __init__(self):
		Choose.__init__(self, 'PSX Libraries', [ ["Address", 30], ["Info", 30] ])
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
		b = Byte(self.CURADDRESS)
		self.CURADDRESS = self.CURADDRESS + 1
		return b

	def TryDecodeID(self, addr):
		decoded = ""

		self.CURADDRESS = addr

		# list from printver 1.11
		PSXLIBNAMES = [
			"libapi",	# 1.02
			"libc",
			"libc2",
			"libcard",
			"libcd",
			"libcomb",
			"libetc",
			"libgpu",
			"libgs",
			"libgte",
			"libgun",
			"libmath",
			"libpad",
			"lib???",
			"libpress",
			"libsio",
			"libsnd",
			"libspu",
			"lib???",
			"lib???",
			"libtap",
			"lib???",
			"libds",
			"lib???",
			"libmcrd",
			"libhmd",
			"libmcx",	# added in 1.11
			"mcgui"		# added in 1.11
		]

		# skip over Ps identifier
		self.GetByte()
		self.GetByte()

		b = self.GetByte()

		# magic check printver does, must be 0
		if (b & 0xC0) == 0:
			# extract possible index
			index = b & 0x3F
			# next 3 bytes must not be 0xFF
			if self.GetByte() != 0xFF and self.GetByte() != 0xFF and self.GetByte() != 0xFF:
				# get major ver byte
				major = self.GetByte()
				if major != 0xFF:
					# get minor ver byte
					minor = self.GetByte()
					if minor != 0xFF:
						# make sure its a known index
						if len(PSXLIBNAMES) > index:
							decoded = decoded + str("(%02d) %s : " % (index, PSXLIBNAMES[index]))
						else:
							decoded = decoded + str("(%02d) %s : ", index, "lib???")

						decoded = decoded + str("%x.%x.%x.%x\n" % ((major & 0xF0) >> 4, major & 0xF, (minor & 0xF0) >> 4, minor & 0xF))

		return decoded

	def process(self):

		found_ea = ida_ida.inf_get_min_ea() - 1
		end_ea = ida_ida.inf_get_max_ea()
		list = []
		
		# letter pattern Ps
		pattern = "50 73"

		while True:
			found_ea = idaapi.find_binary(found_ea+1, end_ea, pattern, 16, idaapi.SEARCH_DOWN)
			if found_ea == idaapi.BADADDR:
				break
			decoded = self.TryDecodeID(found_ea)
			if decoded != "":
				list.append("0x%08X,%s\n" % (found_ea, decoded))

		# turn into showable list
		return [line.rstrip().split(',') for line in list]

def gather_info():
	global chooser
	chooser = MyChoose()
	chooser.show()


#if __name__ == '__main__':
#	gather_info()

gather_info()
