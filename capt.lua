-- Canon Advanced Printing Technology (CAPT) Protocol Dissector
-- For dissecting USB traffic from select Canon laser printer devices
--
-- Copyright (C) 2022 Moses Chong
--
-- Licensed under the GNU General Public License Version 3
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <http://www.gnu.org/licenses/>.

-- SPDX-License-Identifier: GPL-3.0-or-later

-- Opcode mnemonics by Alexey Galakhov and @missla. Adapted from SPECS and
-- src/capt-command.h in the captdriver tree.

--
-- Main Dissectors
--
HOST_PORT = 0xFFFFFFFF  -- USB host in pinfo.dst_port or pinfo.src_port

-- TODO: clean up dissector code

-- Selection Heuristic
--
-- This classifies packets by the first two bytes of the USB bulk transfer
-- payload. If a known CAPT opcode is detected, a suitable dissector is
-- selected.
local last_spd = {} -- last segmented packet data
local response_headers = {} -- header packet number to header content lookup
local response_numbers = {} -- body to header packet number lookup

local function detect_capt(buffer, pinfo, tree)
	buflen = buffer:len()
	if buflen < 1 then return false end
	local size = 0
	local ocd
	if buflen >= 4 then
		local cmd = buffer(0,2):le_uint()
		ocd = opcodes[cmd] or opcodes_prn[cmd]
		size = buffer(2,2):le_uint()
	end
	if not ocd then
		-- pair up response bodies with headers by packet numbers
		test = last_spd.number < pinfo.number
			and last_spd.src_port == pinfo.src_port
			and last_spd.dst_port == pinfo.dst_port
		if test then response_numbers[pinfo.number] = last_spd.number end
	elseif buflen == 6 and size > buflen then
		-- save response headers into lookup
		pn = pinfo.number
		if not response_headers[pn] then
			last_spd.number = pn
			last_spd.src_port = pinfo.src_port
			last_spd.dst_port = pinfo.dst_port
			response_headers[pn] = buffer:bytes()
		end
	end
	capt_proto.dissector(buffer, pinfo, tree)
	return true
end

--
-- Main Dissector
--
-- TODO: make protocol names look prettier in WS
capt_proto = Proto("capt", "Canon Advanced Printing Technology")
opcodes = {
    [0xA0A1] = "CAPT_CHKJOBSTAT",
    [0xA0A8] = "CAPT_XSTATUS",
    [0xA1A0] = "CAPT_IEEE_IDENT",
    [0xA1A1] = "CAPT_IDENT",
    [0xE0A0] = "CAPT_CHKSTATUS",
}
opcodes_prn = {
	[0xA0A0] = "CAPT_NOP", -- classified as a control command to do nothing
	[0xA2A0] = "CAPT_JOB_BEGIN",
	[0xA3A2] = "CAPT_START_0",
	[0xC0A0] = "CAPT_PRINT_DATA",
	[0xC0A4] = "CAPT_PRINT_DATA_END",
	[0xD0A0] = "CAPT_SET_PARM_PAGE",
	[0xD0A1] = "CAPT_SET_PARM_1",
	[0xD0A2] = "CAPT_SET_PARM_2",
	[0xD0A4] = "CAPT_SET_PARM_HISCOA",
	[0xD0A9] = "CAPT_SET_PARMS", -- for multi-command packets
	[0xE0A2] = "CAPT_START_2",
	[0xE0A3] = "CAPT_START_1",
	[0xE0A4] = "CAPT_START_3", -- TODO: should this be re-ordered/renamed?
	[0xE0A5] = "CAPT_UPLOAD_2",
	[0xE0A7] = "CAPT_FIRE", -- start actual printing process for page?
	[0xE0A9] = "CAPT_JOB_END",
	[0xE1A1] = "CAPT_JOB_SETUP",
	[0xE1A2] = "CAPT_GPIO",
}
local capt_comment = ProtoField.string("capt.comment", "Comment")
local capt_stat_cmd = ProtoField.uint16("capt.cmd","Command", base.HEX, opcodes)
local capt_prn_cmd = ProtoField.uint16("capt.cmd","Command", base.HEX, opcodes_prn)
local pkt_size = ProtoField.uint16("capt.packet_size", "Packet Size", base.DEC)
local params = ProtoField.new("Parameters", "capt.param_dump", ftypes.BYTES)
	-- PROTIP: ProtoField.new puts name argument first
local gr_cmd = ProtoField.string("capt.gcmd", "Grouped Command")
capt_proto.fields = {
	capt_comment,
	capt_stat_cmd,
	capt_prn_cmd,
	pkt_size,
	params,
	gr_cmd
}
function capt_proto.dissector(buffer, pinfo, tree)
	local buffer2 = buffer
	local rabytes = ByteArray.new()
    local t_pckt = tree:add(capt_proto, buffer2()) -- heading
	local br_opcode
	local br_size
	local opcode
	local size
	local t_captcmd
	local mne
	if buffer2:len() >= 4 then
		-- read opcode header if plausible
		br_opcode = buffer2(0, 2)
		br_size = buffer2(2, 2)
		opcode = br_opcode:le_uint()
		size = br_size:le_uint()
	end
	if opcodes[opcode] then
		mne = opcodes[opcode]
		t_captcmd = t_pckt:add_le(capt_stat_cmd, br_opcode)
		pinfo.cols.protocol = "CAPT Status Monitor"
		pinfo.cols['info']:set(mne)
		t_captcmd:add_le(pkt_size, br_size)
	elseif opcodes_prn[opcode] then
		mne = opcodes_prn[opcode]
		pinfo.cols.protocol = "CAPT Device Control"
		t_captcmd = t_pckt:add_le(capt_prn_cmd, br_opcode)
		pinfo.cols['info']:append(string.format(" %s ", mne))
		t_captcmd:add_le(pkt_size, br_size)
	elseif not opcodes_prn[opcode] or opcodes[opcode] then
		local hn = response_numbers[pinfo.number]
		if hn then
			local hbytes = response_headers[hn]
			local hopcode = tonumber(hbytes:tvb():range(0,2):le_uint())
			mne = opcodes_prn[hopcode] or opcodes[hopcode]
			pinfo.cols.info:set(mne)
			pinfo.cols.protocol = "CAPT Response Body"
			t_captcmd = t_pckt:add(capt_comment, string.format("Reassembled response using header from Frame %d", hn))
			rabytes:append(hbytes)
			rabytes:append(buffer2:bytes())
			buffer2 = rabytes:tvb('Response')
			-- re-read after reassembling packet
			br_opcode = buffer2(0, 2)
			br_size = buffer2(2, 2)
			size = br_size:le_uint()
			opcode = br_opcode:le_uint()
			t_captcmd:add_le(capt_stat_cmd, br_opcode)
				-- TODO: some control commands have long replies too!
			t_captcmd:add_le(pkt_size, br_size)
		else
			t_captcmd = t_pckt:add(capt_comment, string.format("Unsupported Opcode"))
		end
	end
	if opcode == 0xD0A9 then
		-- dissect multi-command packet
		local i = 4
		while i < size do
			local n = buffer2(i+2, 2):le_uint()
			local gr_op_num = buffer2(i, 2):le_uint()
			local gr_mne = opcodes_prn[gr_op_num]
			local gr_op_mne = string.format("%s (0x%x)", gr_mne, gr_op_num)
			local t_gcmd = t_captcmd:add(gr_cmd, buffer2(i, n), gr_op_mne)
			capt_proto.dissector(buffer2(i, n):tvb(), pinfo, t_gcmd)
			i = i + n -- is there a Lua increment operator?
		end
	elseif size > 4 then
		if size > buffer2:len() then
			t_captcmd:add(capt_comment, "See next Response Body from this source to host for remaining data")
		else
			local n = size - 4
			local br_parm = buffer2(4, n)
			t_captcmd:add(params, br_parm)
			-- select sub-dissector
			if opcode == 0xA1A1 then
				a1a1_proto.dissector(br_parm:tvb(), pinfo, t_captcmd)
			elseif opcode == 0xD0A0 then
				d0a0_proto.dissector(br_parm:tvb(), pinfo, t_captcmd)
			elseif opcode == 0xD0A4 then
				d0a4_proto.dissector(br_parm:tvb(), pinfo, t_captcmd)
			elseif opcode == 0xE1A1 then
				e1a1_proto.dissector(br_parm:tvb(), pinfo, t_captcmd)
			end
		end
	end
end

--
-- Device Control Sub-Dissectors
--

-- 0xA1A1: CAPT_IDENT
local prefix = "capt_ident"
local a1a1_mag_a = ProtoField.uint16(prefix .. ".magic_a", "Magic Number A")
local a1a1_mag_b = ProtoField.uint16(prefix .. ".magic_b", "Magic Number B")
local a1a1_mag_c = ProtoField.uint16(prefix .. ".magic_c", "Magic Number C")
local a1a1_mag_d = ProtoField.uint16(prefix .. ".magic_d", "Magic Number D")
local a1a1_mag_npt = ProtoField.uint8(prefix .. ".magic_npt", "Top Non-printable Margin(?)")
local a1a1_mag_npb = ProtoField.uint8(prefix .. ".magic_npb", "Bottom Non-printable Margin(?)")
local a1a1_mag_npl = ProtoField.uint8(prefix .. ".magic_npl", "Left Non-printable Margin(?)")
local a1a1_mag_npr = ProtoField.uint8(prefix .. ".magic_npr", "Right Non-printable Margin(?)")
local a1a1_mag_rx = ProtoField.uint16(prefix .. ".magic_rx", "X Resolution(?)")
local a1a1_mag_ry = ProtoField.uint16(prefix .. ".magic_ry", "Y Resolution(?)")
a1a1_proto = Proto(prefix, "CAPT: Printer Information")
a1a1_proto.fields = {
	a1a1_mag_a,
	a1a1_mag_b,
	a1a1_mag_c,
	a1a1_mag_d,
	a1a1_mag_npt,
	a1a1_mag_npb,
	a1a1_mag_npl,
	a1a1_mag_npr,
	a1a1_mag_rx,
	a1a1_mag_ry
}
function a1a1_proto.dissector(buffer, pinfo, tree)
	tree:add_le(a1a1_mag_a, buffer(0,2))
	tree:add_le(a1a1_mag_b, buffer(2,2))
	tree:add_le(a1a1_mag_c, buffer(4,2))
	tree:add_le(a1a1_mag_d, buffer(6,2))
	tree:add_le(a1a1_mag_npt, buffer(40,1))
	tree:add_le(a1a1_mag_npb, buffer(41,1))
	tree:add_le(a1a1_mag_npl, buffer(42,1))
	tree:add_le(a1a1_mag_npr, buffer(43,1))
	tree:add_le(a1a1_mag_rx, buffer(44,2))
	tree:add_le(a1a1_mag_ry, buffer(46,2))
end

-- 0xD0A0: CAPT_SET_PARM_PAGE
local prefix = "capt_set_parm_page"
local d0a0_paper_szid = ProtoField.uint8(prefix .. ".paper_size_id", "Paper Size ID", base.HEX)
local d0a0_paper_type = ProtoField.uint8(prefix .. ".paper_type", "Paper Type", base.HEX)
local d0a0_bound_a = ProtoField.uint16(prefix .. ".bound_a", "Bound A", base.DEC)
local d0a0_bound_b = ProtoField.uint16(prefix .. ".bound_b", "Bound B", base.DEC)
local d0a0_raster_w = ProtoField.uint16(prefix .. ".raster_width", "Raster Width (bytes)", base.DEC)
local d0a0_raster_h = ProtoField.uint16(prefix .. ".raster_height", "Raster Height (lines)", base.DEC)
local d0a0_paper_w = ProtoField.uint16(prefix .. ".paper_width", "Paper Width (px)", base.DEC)
local d0a0_paper_h = ProtoField.uint16(prefix .. ".paper_height", "Paper Height (px)", base.DEC)
local d0a0_fuser_mode = ProtoField.uint8(prefix .. ".fuser_mode", "Fuser Mode", base.HEX)
d0a0_proto = Proto("capt_prn_d0a0", "CAPT: Page Parameters")
d0a0_proto.fields = {
	d0a0_paper_szid,
	d0a0_paper_type,
	d0a0_bound_a,
	d0a0_bound_b,
	d0a0_raster_w,
	d0a0_raster_h,
	d0a0_paper_w,
	d0a0_paper_h,
	d0a0_fuser_mode,
}
function d0a0_proto.dissector(buffer, pinfo, tree)
	tree:add(d0a0_paper_szid, buffer(5,1))
	tree:add(d0a0_paper_type, buffer(12,1))
	tree:add_le(d0a0_bound_a, buffer(22,2))
	tree:add_le(d0a0_bound_b, buffer(24,2))
	tree:add_le(d0a0_raster_w, buffer(26,2))
	tree:add_le(d0a0_raster_h, buffer(28,2))
	tree:add_le(d0a0_paper_w, buffer(30,2))
	tree:add_le(d0a0_paper_h, buffer(32,2))
	if buffer:len() >= 34 then
		tree:add(d0a0_fuser_mode, buffer(36,1))
	end
end

-- 0xD0A4: CAPT_SET_PARM_HISCOA
local prefix = 'capt_set_parm_hiscoa'
local d0a4_L3 = ProtoField.int8(prefix .. ".L3", "L3", base.DEC)
local d0a4_L5 = ProtoField.int8(prefix .. ".L5", "L5", base.DEC)
local d0a4_mag_a = ProtoField.int8(prefix .. ".magic_a", "Magic Number A", base.DEC)
local d0a4_mag_b = ProtoField.int8(prefix .. ".magic_b", "Magic Number B", base.DEC)
local d0a4_L0 = ProtoField.int8(prefix .. ".L0", "L0", base.DEC)
local d0a4_L2 = ProtoField.int8(prefix .. ".L2", "L2", base.DEC)
local d0a4_L4 = ProtoField.int16(prefix .. ".L4", "L4", base.DEC)
d0a4_proto = Proto("capt_prn_d0a4", "CAPT: HiSCoA Parameters")
d0a4_proto.fields = {
	d0a4_L3, d0a4_L5, d0a4_mag_a, d0a4_mag_b, d0a4_L0, d0a4_L2, d0a4_L4
}

function d0a4_proto.dissector(buffer, pinfo, tree)
	tree:add(d0a4_L3, buffer(0,1))
	tree:add(d0a4_L5, buffer(1,1))
	tree:add(d0a4_mag_a, buffer(2,1))
	tree:add(d0a4_mag_b, buffer(3,1))
	tree:add(d0a4_L0, buffer(4,1))
	tree:add(d0a4_L2, buffer(5,1))
	tree:add_le(d0a4_L4, buffer(6,2))
end

-- E1A1: CAPT_JOB_SETUP
-- NOTE: the name is a bit of a misnomer as this command doesn't set up
-- a job, but it tells the printer which job it is at, and at what stage
local prefix = 'capt_job_setup'
local e1a1_resp = ProtoField.uint16(prefix .. ".response_code", "Response Code")
local e1a1_mag_a = ProtoField.uint16(prefix .. ".magic_a", "Magic Number A", base.DEC)
local e1a1_host_len = ProtoField.uint16(prefix .. ".hostname_length", "Hostname Length", base.DEC)
local e1a1_usrn_len = ProtoField.uint16(prefix .. ".username_length", "Username Length", base.DEC)
local e1a1_docn_len = ProtoField.uint16(prefix .. ".docname_length", "Document Name Length", base.DEC)
	-- host, user, document name length suspected to be uint16
local e1a1_mag_b = ProtoField.uint8(prefix .. ".magic_b", "Magic Number B", base.DEC)
local e1a1_mag_c = ProtoField.uint8(prefix .. ".magic_c", "Magic Number C", base.DEC)
local e1a1_mag_d = ProtoField.uint16(prefix .. ".magic_d", "Magic Number D", base.DEC)
local e1a1_mag_e = ProtoField.int16(prefix .. ".magic_e", "Magic Number E", base.DEC)
local e1a1_mag_f = ProtoField.int16(prefix .. ".magic_f", "Magic Number F", base.DEC)
local e1a1_year = ProtoField.uint16(prefix .. ".year", "Year", base.DEC)
local e1a1_month = ProtoField.uint8(prefix .. ".month", "Month", base.DEC)
local e1a1_day = ProtoField.uint8(prefix .. ".day", "Day", base.DEC)
local e1a1_hr = ProtoField.uint8(prefix .. ".hour", "UTC(?) Hour", base.DEC)
local e1a1_min = ProtoField.uint8(prefix .. ".minute", "UTC(?) Minute", base.DEC)
local e1a1_sec = ProtoField.uint8(prefix .. ".second", "Second", base.DEC)
local e1a1_mag_g = ProtoField.uint8(prefix .. ".magic_g", "Magic Number G", base.DEC)
e1a1_proto = Proto("capt_prn_e1a1", "CAPT: Job Parameters")
e1a1_proto.fields = {
	e1a1_resp,
	e1a1_mag_a,
	e1a1_host_len,
	e1a1_usrn_len,
	e1a1_docn_len,
	e1a1_mag_b,
	e1a1_mag_c,
	e1a1_mag_d,
	e1a1_mag_e,
	e1a1_mag_f,
	e1a1_year,
	e1a1_month,
	e1a1_day,
	e1a1_hr,
	e1a1_min,
	e1a1_sec,
	e1a1_mag_g,
}
function e1a1_proto.dissector(buffer, pinfo, tree)
	if pinfo.dst_port == HOST_PORT then
		tree:add_le(e1a1_resp, buffer(0,2))
		return true
	else
		tree:add(e1a1_mag_a, buffer(4,1))
		tree:add_le(e1a1_host_len, buffer(8,2))
		tree:add_le(e1a1_usrn_len, buffer(10,2))
		tree:add_le(e1a1_docn_len, buffer(12,2))
		tree:add(e1a1_mag_b, buffer(16,1))
		tree:add(e1a1_mag_c, buffer(17,1))
		tree:add_le(e1a1_mag_d, buffer(18,2))
		tree:add_le(e1a1_mag_e, buffer(20,2))
		tree:add_le(e1a1_mag_f, buffer(22,2))
		tree:add_le(e1a1_year, buffer(24,2))
		tree:add(e1a1_month, buffer(26,1))
		tree:add(e1a1_day, buffer(27,1))
		tree:add(e1a1_hr, buffer(28,1))
		tree:add(e1a1_min, buffer(29,1))
		tree:add(e1a1_sec, buffer(30,1))
		tree:add(e1a1_mag_g, buffer(31,1))
		return true
	end
end

--
capt_proto:register_heuristic("usb.bulk", detect_capt)
