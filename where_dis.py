# Where Dis
# by tomsons26
#
# Adds the ability to check what module address relates to
#	to do this it uses a premade list, list is a text file in this format
#	(0x00563D10, 0x006D4790, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00806D90, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, "movies.obj")
#	with addresses specifying .text, .rdata, .rdata$r, .xdata, .crt$xcu, .data, .data$r, .bss, .comm, .const, .tls
#	list can have comments prefixing with #
#
# The option to use it shows up in rightclick menu of the disassembly view
#	'WhereDis' where dis'es
#	'Reload WhereDis' reloads the list
#	'Debug WhereDis' reports current mapping
#		used to check for duplicates in list but don't see how it can work in this revision of the script
#
# TODO:
#	cleanup??? surely all this hook stuff isn't needed...?
#	restore duplicate checking??
#
#	Copy the 'where_dis.py' into the plugins directory of IDA
#	modify WHERE_DIS_INFO_PATH as needed

WHERE_DIS_INFO_PATH = "D://Temp//" + "where_info" + ".txt"

import sys
from ast import literal_eval
import ida_kernwin
import ida_lines
import idaapi


popup_action_names = []

class hook_helper(idaapi.UI_Hooks):
	def __init__(self):
		idaapi.UI_Hooks.__init__(self)

	def finish_populating_widget_popup(self, form, popup):
		global popup_action_names
		form_type = idaapi.get_widget_type(form)
		if form_type == idaapi.BWN_DISASM:
			for action_name in popup_action_names:
				idaapi.attach_action_to_popup(form, popup, action_name, None)

class action_helper(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def update(self, ctx):
		return idaapi.AST_ENABLE_FOR_WIDGET if ctx.form_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_WIDGET

known_objects = {}

# Sentinel values to ignore
INVALIDS = {0xFFFFFFFF, 0x00000000}

# Fixed section order for each address slot
SECTIONS = [
	".text",
	".rdata",
	".rdata$r",
	".xdata",
	".crt$xcu",
	".data",
	".data$r",
	".bss",
	".comm",
	".const",
	".tls",
]

def parse_objects_from_file():
	global known_objects
	"""
	Parse tuples like:
	(0x00685730, 0x006D9E40, ..., "object.obj")
	Returns dict: { "object.obj": [ {addr, section}, ... ] }
	"""
	f = open(WHERE_DIS_INFO_PATH, "r")
	if f:
		for line in f:
			line = line.strip()
			if not line.startswith("("):
				continue
			if line.startswith("#"):
				continue
			try:
				parts = line.strip("()").split(",")
				*addr_parts, obj_name = parts
				obj_name = obj_name.strip().strip('"')
				entries = []
				for idx, p in enumerate(addr_parts):
					p = p.strip()
					if p.startswith("0x"):
						val = int(p, 16)
						if val not in INVALIDS:
							section = SECTIONS[idx] if idx < len(SECTIONS) else f"slot{idx}"
							entries.append({"addr": val, "section": section})
				if obj_name not in known_objects:
					known_objects[obj_name] = []
				known_objects[obj_name].extend(entries)
			except Exception as e:
				print(f"Parse error on line: {line}, {e}")
		f.close()
	else:
		print("WhereDis can't open %s" % WHERE_DIS_INFO_PATH)

class WhereDisPlugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_PROC
	comment = "Check where this symbol was in"
	help = ""
	wanted_name = "WhereDis"
	wanted_hotkey = ""

	def init(self):
		global known_objects
		idaapi.msg("WhereDis init\n")
		AddToPopup('wheredisaction:where_action', 'WhereDis', WhereDisAction(), None, None)
		AddToPopup('wheredisaction:where_xref_action', 'WhereDis XRef', WhereDisXRefAction(), None, None)
		AddToPopup('wheredisaction:reload_action', 'Reload WhereDis', WhereDisReloadAction(), None, None)
		AddToPopup('wheredisaction:debug_action', 'Debug WhereDis', WhereDisDebugAction(), None, None)
		
		parse_objects_from_file()

		self.hooks = hook_helper()
		self.hooks.hook()
		return idaapi.PLUGIN_KEEP

	def run(self):
		idaapi.msg("WhereDis run\n")

	def term(self):
		idaapi.msg("WhereDis term\n")
		if self.hooks:
			self.hooks.unhook()
		idaapi.unregister_action('wheredisaction:where_action')
		idaapi.unregister_action('wheredisaction:where_xref_action')
		idaapi.unregister_action('wheredisaction:reload_action')
		idaapi.unregister_action('wheredisaction:debug_action')


def find_lesser_closest_object(known_objects, input_addr):
	"""
	Return (object_name, closest_addr, delta, section).
	"""
	closest_obj = None
	closest_entry = None
	closest_delta = None

	for obj, entries in known_objects.items():
		for entry in entries:
			addr = entry["addr"]
			if addr <= input_addr:
				delta = input_addr - addr
				if closest_delta is None or delta < closest_delta:
					closest_delta = delta
					closest_obj = obj
					closest_entry = entry

	if closest_obj:
		return closest_obj, closest_entry["addr"], closest_delta, closest_entry["section"]
	return None, None, None, None


addr_modes = [
	"Address  ",
	"Code From",
	"Code To  ",
	"Data From",
	"Data To  ",
]

def check_chosen_address(mode):
	t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
	if idaapi.read_selection(view, t0, t1):
		start, end = t0.place(view).toea(), t1.place(view).toea()
		end += idaapi.get_item_size(end)
	else:
		start = idaapi.get_screen_ea()

		if start == idaapi.BADADDR:
			return 0

		end = start + idaapi.get_item_size(start)

	if start == idaapi.BADADDR:
		return 0

	if start == end:
		return 0

	x = start
	while x < end:
		# just this address
		if mode == 0:
			address = x
		# code xref from/to
		elif mode == 1:
			address = idaapi.get_first_fcref_from(x)
		elif mode == 2:
			address = idaapi.get_first_fcref_to(x)
		# data xref from/to
		elif mode == 3:
			address = idaapi.get_first_dref_from(x)
		elif mode == 4:
			address = idaapi.get_first_dref_to(x)

		if address != 0xFFFFFFFF:
			
			"""
			for astart, aend, filename in known_objects:
				if address >= astart and address < aend:
					print(format("0x%08X - %s" % (address, filename)))
					break
			"""
			obj, closest_addr, delta, section = find_lesser_closest_object(known_objects, address)
			if obj:
				print(f"{x:#x} {addr_modes[mode]} - {obj} at {hex(closest_addr)} (delta {delta:#x}, section {section})")
			else:
				print(f"{x:#x} {addr_modes[mode]} No matching object found.")
		else:
			print(f"{x:#x} {addr_modes[mode]} No matching object found.")

		isize = idaapi.get_item_size(x)
		if isize != 0:
			x = x + isize
		else:
			x = x + 1

	return 1

class WhereDisAction(action_helper):
	def activate(self, ctx):
		global known_objects
		if len(known_objects) == 0:
			print("known_objects empty!!!!!!")
			return 1
		check_chosen_address(0)
		return 1

class WhereDisXRefAction(action_helper):
	def activate(self, ctx):
		global known_objects
		if len(known_objects) == 0:
			print("known_objects empty!!!!!!")
			return 1
		# just wholesale print all for now cause IDA xref API is annoying
		check_chosen_address(1)
		check_chosen_address(2)
		check_chosen_address(3)
		check_chosen_address(4)
		return 1

class WhereDisReloadAction(action_helper):
	def activate(self, ctx):
		global known_objects
		if len(known_objects) != 0:
			del known_objects #[:]
			known_objects = {}
		parse_objects_from_file()
		#print(known_objects)
		print("WhereDis list reloaded")
		return 1
		
class WhereDisDebugAction(action_helper):
	def activate(self, ctx):
		global known_objects

		"""
		Print a table of all objects with their addresses grouped by section.
		"""
		print("\n=== Section Map ===")
		for obj, entries in known_objects.items():
			print(f"\nObject: {obj}")
			section_map = {}
			for entry in entries:
				sec = entry["section"]
				addr = entry["addr"]
				section_map.setdefault(sec, []).append(addr)
			for sec in SECTIONS:
				if sec in section_map:
					addrs = ", ".join(hex(a) for a in section_map[sec])
					print(f"  {sec:<10} -> {addrs}")

		"""
		if len(known_objects) != 0:
			# check for duplicates
			for i, (s1, en1, f1) in enumerate(known_objects):
				for j, (s2, en2, f2) in enumerate(known_objects):
					if i == j:
						continue
					if s1 > s2 and s1 < en2:
						if s1 != 0 and s2 != 0:
							print("0x%08X overlaps 0x%08X" % (s1, s2))
		else:
			print("known_objects empty!!!!!!")
		
		
		print("WhereDis list debug end")
		"""
		return 1

def AddToPopup(action_name, display, handler, shortcut, tooltip, icon=None):
	global popup_action_names

	if tooltip == None:
		tooltip = action_name

	if idaapi.register_action(idaapi.action_desc_t(action_name, display, handler, shortcut, tooltip)):
		popup_action_names.append(action_name)
	else:
		print('WhereDis Error registering action %s' % (action_name))
 
def PLUGIN_ENTRY(*args, **kwargs):
	return WhereDisPlugin()