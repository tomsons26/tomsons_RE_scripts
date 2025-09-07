#
# Dynamic Init Namer written specifically for TS/RA2/YR
# by tomsons26
#

import idaapi
import idc

#mask to use for byte patterns, TODO probably need better solution
MASK = 0x7F

def do_cmp(ea, base, data):
	test = data

	if len(base) != len(test) :
		print("wrong signature length %d %d" % (len(base), len(test)))
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

def compare_pattern(ea, s):
	# make pattern from string
	tokens = s.split()
	p = []
	for token in tokens:
		if token == '?':
			p.append(MASK)
		else:
			p.append(int(token, 16))

	# base bytes
	b = get_bytes(ea, len(p))
	if do_cmp(ea, p, b) == 1: 
		return 1
	return 0

def do_renaming(ea):
	p = "DD 05 ? ? ? ? DC 0D ? ? ? ? DD 1D ? ? ? ? C3"
	if compare_pattern(ea, p) == 1:
		faddr = get_wide_dword(ea + 2)
		if GetDouble(faddr) == 0.017453292519943295:
			ida_name.set_name(
			faddr,
			"?ONE_RAD@@3NA" + "@" + hex(faddr),
			1
			)
			faddr = get_wide_dword(ea + 2 + 6)
			if GetDouble(faddr) == 45.0:
				ida_name.set_name(
				ea, 
				"??__ERAD_45@@YAXXZ" + "@" + hex(ea), 
				1
				)
			
				ida_name.set_name(
				get_wide_dword(ea + 2 + 6 + 6),
				"?RAD_45@@3NA" + "@" + hex(ea),
				1
				)
				return 1
			elif GetDouble(faddr) == 60.0:
				ida_name.set_name(
				ea, 
				"??__ERAD_60@@YAXXZ" + "@" + hex(ea), 
				1
				)
			
				ida_name.set_name(
				get_wide_dword(ea + 2 + 6 + 6),
				"?RAD_60@@3NA" + "@" + hex(ea),
				1
				)
				return 1
			elif GetDouble(faddr) == 90.0:
				ida_name.set_name(
				ea, 
				"??__ERAD_90@@YAXXZ" + "@" + hex(ea), 
				1
				)
			
				ida_name.set_name(
				get_wide_dword(ea + 2 + 6 + 6),
				"?RAD_90@@3NA" + "@" + hex(ea),
				1
				)
				return 1
			else:
				print("failed %x %f" % (ea, GetDouble(faddr)))
				return 0
		else:
			print("failed %x %f" % (ea, GetDouble(faddr)))
			return 0
	
	
	p = "DD 05 ? ? ? ? DD 05 ? ? ? ? E8 ? ? ? ? DC C0 83 EC 08 DD 1C 24 E8 ? ? ? ? DD 1D ? ? ? ? 83 C4 08 C3"
	if compare_pattern(ea, p) == 1:
		faddr = get_wide_dword(ea + 2);
		if GetDouble(faddr) == 256.0:
			ida_name.set_name(
			ea, 
			"??__ECELL_LEPTON_DIAG@@YAXXZ" + "@" + hex(ea), 
			1
			)
		
			ida_name.set_name(
			get_wide_dword((ea + 0x1E) + 2),
			"?CELL_LEPTON_DIAG@@3NA" + "@" + hex(ea),
			1
			)
			return 1
		elif GetDouble(faddr) == 34.0:
			ida_name.set_name(
			ea, 
			"??__EISO_TILE_SIZE@@YAXXZ" + "@" + hex(ea), 
			1
			)
		
			ida_name.set_name(
			get_wide_dword((ea + 0x1E) + 2),
			"?ISO_TILE_SIZE@@3NA" + "@" + hex(ea),
			1
			)
			return 1
		else:
			print("failed %x %f %d" % (ea, GetDouble(faddr), GetDouble(faddr) == 256.0))
			return 0

	p = "DD ? ? ? ? ? E8 ? ? ? ? A3 ? ? ? ? C3 90"
	if compare_pattern(ea, p) == 1:
		faddr = get_wide_dword(ea + 2)
		raddr = get_first_dref_to(faddr)

		p = "DD 05 ? ? ? ? DD 05 ? ? ? ? E8 ? ? ? ? DC C0 83 EC 08 DD 1C 24 E8 ? ? ? ? DD 1D ? ? ? ? 83 C4 08 C3"
		if compare_pattern(raddr - 0x1E, p) == 1:
			ida_name.set_name(
			ea, 
			"??__EISO_TILE_PIXEL_W@@YAXXZ" + "@" + hex(ea), 
			1
			)
		
			ida_name.set_name(
			get_wide_dword((ea + 0x0B) + 1), 
			"?ISO_TILE_PIXEL_W@@3HA" + "@" + hex(ea),
			1
			)
			return 1
		else:
			print("failed %x %f" % (ea, GetDouble(faddr)))
			return 0

	p = "A1 ? ? ? ? 8B 0D ? ? ? ? 50 51 E8 ? ? ? ? DC 0D ? ? ? ? 83 C4 08 E8 ? ? ? ? A3 ? ? ? ? C3"
	if compare_pattern(ea, p) == 1:
		ida_name.set_name(
		ea, 
		"??__EISO_TILE_PIXEL_H@@YAXXZ" + "@" + hex(ea), 
		1
		)
	
		ida_name.set_name(
		get_wide_dword((ea + 0x20) + 1), 
		"?ISO_TILE_PIXEL_H@@3HA" + "@" + hex(ea),
		1
		)
		return 1

	p = "DD 05 ? ? ? ? DC 25 ? ? ? ? 83 EC 08 DD 1C 24 E8 ? ? ? ? DC 0D ? ? ? ? 83 C4 08 DC 0D ? ? ? ? E8"
	if compare_pattern(ea, p) == 1:
		ida_name.set_name(
		ea, 
		"??__ELEVEL_LEPTON_H@@YAXXZ" + "@" + hex(ea), 
		1
		)
	
		ida_name.set_name(
		get_wide_dword((ea + 0x2B) + 1), 
		"?LEVEL_LEPTON_H@@3HA" + "@" + hex(ea),
		1
		)
		return 1

	p = "DB 05 ? ? ? ? 83 EC 08 DC 0D ? ? ? ? DD 1C 24 E8 ? ? ? ? DD 1D ? ? ? ? 83 C4 08 C3"
	if compare_pattern(ea, p) == 1:
		ida_name.set_name(
		ea, 
		"??__ECELL_SLOPE_ANGLE@@YAXXZ" + "@" + hex(ea), 
		1
		)
	
		ida_name.set_name(
		get_wide_dword((ea + 0x17) + 2), 
		"?CELL_SLOPE_ANGLE@@3NA" + "@" + hex(ea),
		1
		)
		return 1

	p = "51 A1 ? ? ? ? 83 EC 08 8D 0C 00 89 4C 24 08 DB 44 24 08 DC 35 ? ? ? ? DD 1C 24 E8 ? ? ? ? DD 1D ? ?"
	if compare_pattern(ea, p) == 1:
		ida_name.set_name(
		ea, 
		"??__ECELL_DIAG_SLOPE_ANGLE@@YAXXZ" + "@" + hex(ea),
		1
		)
	
		ida_name.set_name(
		get_wide_dword((ea + 0x22) + 2), 		
		"?CELL_DIAG_SLOPE_ANGLE@@3NA" + "@" + hex(ea),
		1
		)
		return 1

	p = "51 A1 ? ? ? ? 8D 0C 85 ? ? ? ? 89 4C 24 00 DB 44 24 00 DC 05 ? ? ? ? E8 ? ? ? ? A3 ? ? ? ? 59 C3"
	if compare_pattern(ea, p) == 1:
		ida_name.set_name(
		ea, 
		"??__EBRIDGE_LEPTON_HEIGHT@@YAXXZ" + "@" + hex(ea), 
		1
		)
	
		ida_name.set_name(
		get_wide_dword((ea + 0x20) + 1), 
		"?BRIDGE_LEPTON_HEIGHT@@3HA" + "@" + hex(ea),
		1
		)
		return 1

	p = "A1 ? ? ? ? 99 2B C2 D1 F8 A3 ? ? ? ? C3"
	if compare_pattern(ea, p) == 1:
		ida_name.set_name(
		ea, 	
		"??__ECELL_PIXEL_H_HALF@@YAXXZ" + "@" + hex(ea), 
		1
		)
	
		ida_name.set_name(
		get_wide_dword((ea + 0xA) + 1), 		
		"?CELL_PIXEL_H_HALF@@3HA" + "@" + hex(ea),
		1
		)
		return 1

	p = "90 A1 ? ? ? ? A3 ? ? ? ? C3 90"
	if compare_pattern(ea - 1, p) == 1:
		ida_name.set_name(
		ea, 	
		"??__ECELL_PIXEL_H_HALF_1@@YAXXZ" + "@" + hex(ea), 
		1
		)
	
		ida_name.set_name(
		get_wide_dword((ea + 0x5) + 1), 		
		"?CELL_PIXEL_H_HALF_1@@3HA" + "@" + hex(ea),
		1
		)
		return 1

	p = "90 33 C0 66 A3 ? ? ? ? 66 A3 ? ? ? ? C3 90"
	if compare_pattern(ea - 1, p) == 1:
		ida_name.set_name(
		ea,
		"??__ECELL_NONE@@YAXXZ" + "@" + hex(ea),
		1
		)
	
		ida_name.set_name(
		get_wide_dword((ea + 2) + 2), 		
		"?CELL_NONE@@3VCell@@A" + "@" + hex(ea),
		1
		)
		return 1

	p = "90 33 C0 A3 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? C3 90"
	if compare_pattern(ea - 1, p) == 1:
		ida_name.set_name(
		ea,
		"??__ECOORD_NONE@@YAXXZ" + "@" + hex(ea),
		1
		)
	
		ida_name.set_name(
		get_wide_dword((ea + 2) + 1),
		"?COORD_NONE@@3VCoord@@A" + "@" + hex(ea),
		1
		)
		return 1

	p = "33 C0 A3 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? C3 90"
	if compare_pattern(ea, p) == 1:
		ida_name.set_name(
		ea,
		"??__ERECT_NONE@@YAXXZ" + "@" + hex(ea),
		1
		)
	
		ida_name.set_name(
		get_wide_dword((ea + 2) + 1),
		"?RECT_NONE@@3VRect@@A" + "@" + hex(ea),
		1
		)
		return 1
		
	"""
	p = "33 C0 68 ? ? ? ? A3 ? ? ? ? A3 ? ? ? ? C6 05 ? ? ? ? ? A2 ? ? ? ? C7 05 ? ? ? ? ? ? ? ? C7 05 ? ? ?"
	if compare_pattern(ea, p) == 1:
		ida_name.set_name(
		ea,
		"_static_init_dvc" + "@" + hex(ea),
		1
		)
		
		ida_name.set_name(
		get_wide_dword(ea + 2 + 1),
		"_static_deinit_dvc" + "@" + hex(ea),
		1
		)
		return 1
		
	p = "B8 ? ? ? ? B9 00 01 00 00 32 D2 88 50 FE 88 50 FF 88 10 83 C0 03 49 75 F2 C3"
	if compare_pattern(ea, p) == 1:
		ida_name.set_name(
		ea,
		"_static_init_palette" + "@" + hex(ea),
		1
		)
		return 1
		
	p = "51 ? ? B9 ? ? ? ? 88 44 24 00 88 44 24 01 88 44 24 02 8D 44 24 00 50 E8 ? ? ? ? 59 C3"
	if compare_pattern(ea, p) == 1:
		ida_name.set_name(
		ea,
		"_static_init_palette" + "@" + hex(ea),
		1
		)
		return 1
	"""

	return 0
		

addr = 0
parse = 0

# !! change segment name if needed
segm = get_segm_start(get_segm_by_sel(selector_by_name(".data")))
print("segment at 0x%X\n" % segm);

# is the address valid, does it start with 0 as MSVC dyn init list starts, is it a msvc binary
if (segm != idaapi.BADADDR) and get_wide_dword(segm) == 0 and idc.get_inf_attr(INF_COMPILER) == COMP_MS:
	# skip over the 0
	addr = segm + 4
	parse = 1

if parse:
	i = 0
	while 1:

		# end of list
		if get_wide_dword(addr) == 0:
			print("Reached end of list, marked %d\n" % i)
			break

		if i == 10000:
			print("Bugs happened, attempted to process absurd amount\nBaling to prevent inifnite loop\nLast address %X\n" % addr)
			break

		i = i + 1

		ea = get_wide_dword(addr)
		res = do_renaming(ea)
		#if res:
		#	print("named %x" % ea)
		res = 0

		addr = addr + 4
else:
	print("Can't find dynamic init list or binary not compatible with script!\n")
