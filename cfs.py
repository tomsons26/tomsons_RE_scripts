#------------------------------------------------------------------------------
# IDA Plugin to import and export function hashes
#
# To export a list select functions in the "Functions View", rightclick and "Export Hash"
# To import a list "File", "Load File", "CFH Hash File"
#
# Maybe TODO:
#   backport it to IDA 7.0
#
# Quite modified version of https://github.com/cra0/ida-scripts/tree/master/plugins
#   Unlike the original this combines import and export features in same file
#   Unlike original this doesn't check for duplicates as that takes all eternity
#   Unlike original, on import this builds a signature db of the current idb,
#   then compares the signatures to the loaded signatures,
#   this compromise was chosen as binary searching large binaries takes all eternity, this takes minutes
# Copy the 'cvutils-cfs-exporter.py' into the plugins directory of IDA
#------------------------------------------------------------------------------

PLUGIN_NAME = "Import/Export Function Signature Plugin"

__VERSION__ = '0.0.2'
__AUTHOR__ = 'tomsons26, cra0'

import os
import sys
import idc
import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_name
import ida_kernwin
import ida_ua
import ida_ida
import hashlib

from hashlib import sha1

UA_MAXOP=ida_ida.UA_MAXOP

major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)
using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)

idaver_74newer = (major == 7 and minor >= 4)
idaver_8newer = (major >= 8)

if idaver_74newer or idaver_8newer:
	newer_version_compatible = True
else:
	newer_version_compatible = False

if newer_version_compatible:
	#IDA 7.4+
	#https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
	import ida_ida
	import ida_kernwin

if using_pyqt5:
	import PyQt5.QtGui as QtGui
	import PyQt5.QtCore as QtCore
	import PyQt5.QtWidgets as QtWidgets
	from PyQt5.Qt import QApplication

else:
	import PySide.QtGui as QtGui
	import PySide.QtCore as QtCore
	QtWidgets = QtGui
	QtCore.pyqtSignal = QtCore.Signal
	QtCore.pyqtSlot = QtCore.Slot
	from PySide.QtGui import QApplication

class FunctionHash:
	def __init__(self, address, hash):
		self.address = address
		self.hash = hash

# IDA is annoying sometimes making jump tables at end of function part of it so need to fix end..
def FixupFunctionEnd(start, end):
	func = ida_funcs.func_t(start)
	res = ida_funcs.find_func_bounds(func, ida_funcs.FIND_FUNC_EXIST)

	if res == ida_funcs.FIND_FUNC_UNDEF:
		return end
	else:
		return func.end_ea

#------------------------------------------------------------------------------
# Import handler
#------------------------------------------------------------------------------

class ImportFileMenuHandler(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def get_directory_path(self, file_path):
		"""
		Get the directory path from a given file path.
		"""
		return os.path.dirname(file_path)

	def get_file_name(self, file_path):
		"""
		Get the file name from a given file path.
		"""
		return os.path.basename(file_path)


	def build_sig_list(self):
		sig_list = list()
		sig_maker = SigMaker()

		for i, addr in enumerate(idautils.Functions()):
			start = idc.get_func_attr(addr, idc.FUNCATTR_START)
			end = idc.get_func_attr(addr, idc.FUNCATTR_END)
			end = FixupFunctionEnd(start, end)
			func_name = idc.get_func_name(start)

			# We'll create a signature for the entire function
			sig = sig_maker.make_sig_default(start, end)

			if sig is None or sig == "":
				print(f"Failed to make a signature for function {func_name} at {start:x}")
				continue

			sig_list.append(FunctionHash(start, sha1(sig.encode('utf-8')).hexdigest()))

		return sig_list

	def find_hash_match(self, list, hash):
		"""
		Tries to find current signature in the current IDB signature list.
		TODO: maybe handle duplicates
		"""
		matches = []

		for i in list:
			#print("checking {} against {}".format(i.sig, signature))
			if hash in i.hash:
				matches.append(i.address)
				break

		return matches

	def process_signatures(self, sig_file_path):
		"""
		Process the signatures and resolve function names in IDA.
		"""
		counter = 0
		resolved_count = 0
		error_count = 0
		min_ea = idaapi.cvar.inf.min_ea
		max_ea = idaapi.cvar.inf.max_ea
		is_64bit = idc.__EA64__

		print("Processing Hashes...")

		idaapi.show_wait_box("Processing... Please Wait (This may take a bit)")

		sig_list = self.build_sig_list()

		with open(sig_file_path, "r") as sig_file:
			lines = sig_file.readlines()
			count = len(lines)

			for line in lines:

				ida_kernwin.replace_wait_box("Processing hash %d/%d" % (counter, count))

				if ida_kernwin.user_cancelled():
					break

				line = line.strip()

				if not line or line.startswith("//") or line.startswith("*"):
					continue

				# Hash
				hash, line = line.split(",", 1)
				hash = hash.strip()[1:-1]  # Remove surrounding quotes

				print(hash)

				# Function Name
				func_name = line.strip()[3:-1]  # Remove surrounding quotes and //

				print(func_name)

				# Find all matches
				ea = idaapi.BADADDR
				matches = self.find_hash_match(sig_list, hash)
				matches_count = len(matches)
				if matches_count > 1:
					print("Multiple hash matches[%i] found for [%s] ignoring hash." % (matches_count, func_name))
					continue

				# Set EA if we have only 1 hit, change this if you wish.
				if matches_count == 1:
					ea = matches[0]

				#print(f"({resolved_count}/{counter}) [{ea:X}] [{func_name}] ==> ", end="")

				if ea != idaapi.BADADDR:
					if ida_bytes.get_full_flags(ea) != idaapi.BADADDR:
						func_idb_name_str = ida_name.get_name(ea)

						#TODO: remove?
						if idc.get_func_flags(ea) == -1:
							ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 1)
							idc.create_insn(ea)
							ida_funcs.add_func(ea)
							ida_name.set_name(ea, func_name, ida_name.SN_FORCE)
							#idc.set_cmt(ea, "SIG-RESOLVED " + func_name, 1)
							resolved_count += 1
							#print("[RESOLVED]")
						elif func_idb_name_str and len(func_idb_name_str) >= 3:
							# all this crud should be renamed, don't touch anything else
							#if func_idb_name_str[:4] == "sub_" or func_idb_name_str[:3] == "__Z" or "unknown_libname" in func_idb_name_str or "@std@" in func_idb_name_str or "@_STL@" in func_idb_name_str:
							if func_idb_name_str[:4] == "sub_" or func_idb_name_str[:3] == "__Z" or "unknown_libname" in func_idb_name_str:
								ida_name.set_name(ea, func_name, ida_name.SN_FORCE)
								#idc.set_cmt(ea, "SIG-RESOLVED " + func_name, 1)
								resolved_count += 1
								#print("[RENAMED+RESOLVED]", func_idb_name_str, "TO", func_name)
							else:
								print("[IGNORED] Function @ 0x{:X} seems named.".format(ea))
							idc.set_color(ea, 2, 0xd7d7d7)
						else:
							print("[UNKNOWN ERROR]")
					else:
						error_count += 1
						print("[BAD!!!] Unable to resolve =>", func_name, "@ [0x{:X}]".format(ea))
				else:
					print("[NOT FOUND] Hash {} not found in the binary".format(counter))

				counter += 1

		del lines
		del sig_list

		print("------------------------------------------")
		print("Resolved ({}/{}) Functions, {} Lines!".format(resolved_count, counter, count))
		if error_count > 0:
			print("Errors ({})".format(error_count))
			return False

		return True

	def main(self):
		sig_file_path = idaapi.ask_file(0, "*.cfh", "Function Hash Definition File")
		if sig_file_path:
			print("------------------------------------------")
			print(f"{PLUGIN_NAME} {__VERSION__} - {__AUTHOR__}")
			print("Parsing:", sig_file_path)

			# Show the "Please wait" dialog before starting the heavy sigfind operation
			#idaapi.show_wait_box("Processing... Please Wait (This may take a while)")

			if not self.process_signatures(sig_file_path):
			   idaapi.warning("Some errors occurred while importing.")

		# Hide the "Please wait" dialog
		idaapi.hide_wait_box()


	# Invoke the main
	def activate(self, ctx):
		self.main()  # call the main function when the action is activated
		return 1

	# This action is always available.
	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS


#------------------------------------------------------------------------------
# Plugin Main
#------------------------------------------------------------------------------

def PLUGIN_ENTRY():
	"""
	Required plugin entry point for IDAPython Plugins.
	"""
	return CFSSignaturePlugin()

class CFSSignaturePlugin(idaapi.plugin_t):

	flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
	comment = "Import and export function function hashes."
	help = "Select functions right-click, click Export Function Hashes."
	wanted_name = PLUGIN_NAME
	wanted_hotkey = ""

	#--------------------------------------------------------------------------
	# Plugin Overloads
	#--------------------------------------------------------------------------

	def init(self):
		"""
		This is called by IDA when it is loading the plugin.
		"""

		# initialize the menu actions our plugin will inject
		self._init_sig_actions()

		# initialize plugin hooks
		self._init_hooks()

		# done
		idaapi.msg("%s %s initialized...\n" % (PLUGIN_NAME, __VERSION__))
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		"""
		This is called by IDA when this file is loaded as a script.
		"""
		idaapi.msg("%s cannot be run as a script.\n" % PLUGIN_NAME)

	def term(self):
		"""
		This is called by IDA when it is unloading the plugin.
		"""

		# unhook our plugin hooks
		self._hooks.unhook()

		# unregister our actions & free their resources
		self._del_ACTION_EXPORT_SIGNATURES()
		self._del_ACTION_IMPORT_SIGNATURES()


		# done
		idaapi.msg("%s terminated...\n" % self.wanted_name)

	#--------------------------------------------------------------------------
	# Plugin Hooks
	#--------------------------------------------------------------------------

	def _init_hooks(self):
		"""
		Install plugin hooks into IDA.
		"""
		self._hooks = Hooks()
		self._hooks.hook()

	#--------------------------------------------------------------------------
	# IDA Actions
	#--------------------------------------------------------------------------

	ACTION_EXPORT_SIGNATURES  = "cfh:export_signatures"
	ACTION_IMPORT_SIGNATURES  = "cfh:import_action"
	ACTION_TOOLTIP_ICON = 198

	def _init_sig_actions(self):
		"""
		Register the export sigs action with IDA.
		"""
		# If the action is already registered, unregister it first.
		if idaapi.unregister_action(self.ACTION_EXPORT_SIGNATURES):
			idaapi.msg("Warning: action was already registered, unregistering it first\n")

		if (sys.version_info > (3, 0)):
			# Describe the action using python3 copy
			action_desc1 = idaapi.action_desc_t(
				self.ACTION_EXPORT_SIGNATURES,                              # The action name.
				"Export Hashes",                                        # The action text.
				IDACtxEntry(export_signatures_go),                          # The action handler.
				"",                                                         # Optional: action shortcut
				"Export Hashes",                                        # Optional: tooltip
				35,                                                         # Icon
				ida_kernwin.ADF_NO_UNDO
			)
		else:
			# Describe the action using python2 copy
			action_desc1 = idaapi.action_desc_t(
				self.ACTION_EXPORT_SIGNATURES,                          # The action name.
				"Export Hashes",                                    # The action text.
				IDACtxEntry(export_signatures_go),                      # The action handler.
				"",                                                     # Optional: action shortcut
				"Export Hashes",                                    # Optional: tooltip
				35,                                                     # Icon
				ida_kernwin.ADF_NO_UNDO
			)

		# register the action with IDA
		assert idaapi.register_action(action_desc1), "Action registration failed"

		if (sys.version_info > (3, 0)):
			action_desc2 = idaapi.action_desc_t(
				self.ACTION_IMPORT_SIGNATURES,   # The action name.
				'CFS Signature File...',  # The action text.
				ImportFileMenuHandler(),  # The action handler.
				"",   # Optional: the action shortcut.
				'Import Hashes',  # Optional: the action tooltip.
				self.ACTION_TOOLTIP_ICON,
				ida_kernwin.ADF_NO_UNDO
			)
		else:
			# Describe the action using python2 copy
			action_desc2 = idaapi.action_desc_t(
				self.ACTION_IMPORT_SIGNATURES,   # The action name.
				'CFS Signature File...',  # The action text.
				ImportFileMenuHandler(),  # The action handler.
				"",   # Optional: the action shortcut.
				'Import Hashes',  # Optional: the action tooltip.
				self.ACTION_TOOLTIP_ICON,
				ida_kernwin.ADF_NO_UNDO
			)

		# register the action with IDA
		assert idaapi.register_action(action_desc2), "Action registration failed"

		# Attach the action to a menu item in the File menu.
		idaapi.attach_action_to_menu('File/Load file/',   # The relative path of where to add the action.
									  self.ACTION_IMPORT_SIGNATURES,   # The action ID (declared above).
									  idaapi.SETMENU_APP)   # We want to append the action after.


	def _del_ACTION_EXPORT_SIGNATURES(self):
		"""
		Delete the action from IDA.
		"""
		idaapi.unregister_action(self.ACTION_EXPORT_SIGNATURES)

	def _del_ACTION_IMPORT_SIGNATURES(self):
		"""
		Delete the action from IDA.
		"""
		idaapi.unregister_action(self.ACTION_IMPORT_SIGNATURES)



#------------------------------------------------------------------------------
# Plugin Hooks
#------------------------------------------------------------------------------

class Hooks(idaapi.UI_Hooks):

	def __init__(self):
		# Call the __init__ method of the superclass
		super(Hooks, self).__init__()

		# Get the IDA version
		major, minor = map(int, idaapi.get_kernel_version().split("."))
		self.newer_version_compatible = (major == 7 and minor >= 4) or (major >= 8)

		# If the IDA version is less than 7.4, define finish_populating_tform_popup
		if not self.newer_version_compatible:
			self.finish_populating_tform_popup = self._finish_populating_tform_popup

	def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
		"""
		A right click menu is about to be shown. (IDA 7.x)
		"""
		inject_export_signatures_actions(widget, popup_handle, idaapi.get_widget_type(widget))
		return 0


	def _finish_populating_tform_popup(self, form, popup):
		"""
		A right click menu is about to be shown. (IDA 6.x)
		"""
		inject_export_signatures_actions(form, popup, idaapi.get_tform_type(form))
		return 0


#------------------------------------------------------------------------------
# Action Wrappers
#------------------------------------------------------------------------------

def inject_export_signatures_actions(widget, popup_handle, widget_type):
	if widget_type == idaapi.BWN_FUNCS:
		idaapi.attach_action_to_popup(
			widget,
			popup_handle,
			CFSSignaturePlugin.ACTION_EXPORT_SIGNATURES,
			"Export Signatures",
			idaapi.SETMENU_APP
		)
	return 0

#------------------------------------------------------------------------------
# Signature Processing Functions
#------------------------------------------------------------------------------

def add_bytes_to_sig(sig, address, size):
	for i in range(size):
		sig.append("{:02X}".format(idaapi.get_byte(address + i)))

def add_white_spaces_to_sig(sig, size):
	for i in range(size):
		sig.append("?")

def get_current_opcode_size(instruction):
	for i in range(UA_MAXOP):
		if instruction.ops[i].type == ida_ua.o_void:
			return 0, i
		if instruction.ops[i].offb != 0:
			return instruction.ops[i].offb, i
	return 0, 0

def match_operands(instruction, operand, size):
	# Check for data reference
	if idaapi.get_first_dref_from(instruction.ea) != idaapi.BADADDR:
		return False

	if idaapi.get_first_cref_from(instruction.ea) != idaapi.BADADDR: # Code reference
		return False

	return True

def add_ins_to_sig(instruction, sig):
	size, count = get_current_opcode_size(instruction)
	if size == 0:
		add_bytes_to_sig(sig, instruction.ea, instruction.size)
	else:
		add_bytes_to_sig(sig, instruction.ea, size)

	if match_operands(instruction, 0, size):
		add_bytes_to_sig(sig, instruction.ea + size, instruction.size - size)
	else:
		add_white_spaces_to_sig(sig, instruction.size - size)

def is_subOrAdd_instruction(insn):
	# Default bytes of those instructions
	opcode_sub = [0x48, 0x83, 0xEC]
	opcode_add = [0x48, 0x83, 0xC4]

	# Get the bytes of the instruction
	insn_bytes = ida_bytes.get_bytes(insn.ea, insn.size)

	# Convert the byte array to a list of integer byte values
	insn_byte_list = [b for b in insn_bytes]

	# Compare the first three bytes of the instruction with the opcode
	return insn_byte_list[:3] == opcode_sub or insn_byte_list[:3] == opcode_add


class SigMaker:
	def __init__(self):
		pass

	def make_sig_default(self, start, end):
		signature = []
		current_address = start

		#if (end - start) < 5:
		#	print("Signature must be greater than 5 bytes")
		#	return ""

		# this is dragging next function instructions in was "while current_address <= end:"
		while current_address < end:
			instruction = ida_ua.insn_t()
			if ida_ua.decode_insn(instruction, current_address) == 0:
				break

			if instruction.size < 5:
				add_bytes_to_sig(signature, current_address, instruction.size)
			else:
				add_ins_to_sig(instruction, signature)

			current_address += instruction.size

		return " ".join(signature)

	def make_sig_smart(self, start, end):
		signature = []
		current_address = start

		#if (end - start) < 5:
		#	print("Signature must be greater than 5 bytes")
		#	return ""

		while current_address <= end:
			instruction = ida_ua.insn_t()
			if ida_ua.decode_insn(instruction, current_address) == 0:
				break

			#handle sub,add
			if is_subOrAdd_instruction(instruction):
				add_bytes_to_sig(signature, current_address, instruction.size - 1)
				add_white_spaces_to_sig(signature, 1)
				current_address += instruction.size
				continue

			if instruction.size < 5:
				add_bytes_to_sig(signature, current_address, instruction.size)
			else:
				add_ins_to_sig(instruction, signature)

			current_address += instruction.size

		return " ".join(signature)

def export_signatures_go(ctx):
	sig_maker = SigMaker()

	selected_funcs = []
	# fill address array
	for pfn_idx in ctx.chooser_selection:
		pfn = ida_funcs.getn_func(pfn_idx)
		if pfn:
			selected_funcs.append(pfn.start_ea)

	if not selected_funcs:
		print("No functions selected.")
		return

	# Prompt for the output file path
	filename = ida_kernwin.ask_file(1, "*.cfh", "Enter the name of the  file:")
	if not filename:
		print("No file selected.")
		return

	idaapi.show_wait_box("Exporting signatures...")

	if ida_kernwin.user_cancelled():
		return

	# Build sigs and export!
	count = 0
	sig_list = list()

	with open(filename, "w") as file:
		for func_ea in selected_funcs:

			start = idc.get_func_attr(func_ea, idc.FUNCATTR_START)
			end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
			end = FixupFunctionEnd(start, end)
			func_name = idc.get_func_name(start)

			if ida_kernwin.user_cancelled():
				break

			prefix = ""
			# don't need these as signatures import will apply but we do still want to know of them
			if "unknown_libname" in func_name or func_name.startswith("sub_"):
				prefix = "//"

			# We'll create a signature for the entire function
			sig = sig_maker.make_sig_default(start, end)

			if sig is None or sig == "":
				print(f"Failed to make a signature for function {func_name} at {start:x}")
				continue

			prefix = ""
			if (end - start) < 5:
				#print("Signature must be greater than 5 bytes")
				#return ""
				prefix = "*"

			h = sha1(sig.encode('utf-8')).hexdigest()
			#sig_list.append(f"{count},\"{func_name}\",\"{sig}\"\n")
			#sig_list.append(f"{prefix}\"{func_name}\",\"{sig}\"\n")
			#sig_list.append(f"\"{h}\",//\"{func_name}\",\"{sig}\"\n")
			sig_list.append(f"{prefix}\"{h}\",//\"{func_name}\"\n")
			count += 1

		if count:
			# Write the signature to the file
			for line in sig_list:
				file.write(line)

		file.close()

	del sig_list
	del selected_funcs

	idaapi.hide_wait_box()

	print(f"Exported {count} function signatures to {filename}\n")

#------------------------------------------------------------------------------
# IDA ctxt
#------------------------------------------------------------------------------

class IDACtxEntry(idaapi.action_handler_t):

	def __init__(self, action_function):
		idaapi.action_handler_t.__init__(self)
		self.action_function = action_function

	def activate(self, ctx):
		self.action_function(ctx)
		return 1

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS
