# PSX Lib ID finder
# by tomsons26
#
# Scans though sections of the binary
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
		b = ida_bytes.get_byte(self.CURADDRESS)
		self.CURADDRESS = self.CURADDRESS + 1
		return b

	def TryDecodeID(self, addr):
		mode = 0
		decoded = ""

		self.CURADDRESS = addr

		# list from printver 1.11
		PSXLIBNAMES = [
			"libapi",		# pkver handled these
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
			"lib???",		# 13 NOTE printed as libpio in pkver
			"libpress",
			"libsio",
			"libsnd",
			"libspu",
			"lib???",		# 18 NOTE printed as libstd in pkver
			"lib???",		# 19 NOTE printed as libstr in pkver
			"libtap",
			"lib???",		# 21 NOTE printed as libcomb2 in pkver
			"libds",
			"lib???",		# 23 NOTE printed as libmdl in pkver
			"libmcrd",
			"libhmd",		# added in printver 1.02
			"libmcx",		# added in printver 1.11
			"mcgui"			# added in printver 1.11
		]
		LIBCOUNT = len(PSXLIBNAMES)
		
		MONTHS = [
			"Jan",
			"Feb",
			"Mar",
			"Apr",
			"May",
			"Jun",
			"Jul",
			"Aug",
			"Sep",
			"Oct",
			"Nov",
			"Dec",
		]

		# skip over Ps identifier that we already know matches
		b0 = self.GetByte()
		b1 = self.GetByte()

		# while loop lets me keep this easy to read
		while 1:

			# get library index
			b2 = self.GetByte()

			# this byte must not be 0xFF
			if b2 == 0xFF:
				break

			# must be 0 when masked with 0xC0
			if (b2 & 0xC0) != 0:
				break

			index = (b2 & 0x3F)

			# get timestamp
			b3 = self.GetByte()
			b4 = self.GetByte()
			b5 = self.GetByte()

			# these 3 bytes must not be 0xFF
			if b3 == 0xFF or b4 == 0xFF or b5 == 0xFF:
				break

			year = 1996 + (b3 >> 0x04)
			month = (b3 & 0xF)
			day = (b4 >> 0x03)
			hour = ((b4 & 0x07) << 0x02) | (b5 >> 0x06)
			minute = (b5 & 0x3F)

			# get version info
			b6 = self.GetByte()
			b7 = self.GetByte()

			# these bytes must not be 0xFF
			if b6 == 0xFF or b7 == 0xFF:
				break

			major1 = (b6 & 0xF0) >> 0x04
			minor1 = (b6 & 0x0F)
			minor2 = (b7 & 0xF0) >> 0x04
			minor3 = (b7 & 0x0F)

			# make sure its a known index
			if LIBCOUNT > index:
				decoded = decoded + str("(%02d) %s " % (index, PSXLIBNAMES[index]))
			else:
				decoded = decoded + str("(%02d) %s ", index, "lib???")

			decoded = decoded + str("[%x.%x.%x.%x]" % (major1, minor1, minor2, minor3))

			if day != 0:
				decoded = decoded + str(" : %s %02d %04d %02d:%02d" % (MONTHS[month - 1], day, year, hour, minute))

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
		
		# letter pattern Ps
		pattern = "50 73"

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
