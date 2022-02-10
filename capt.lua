-- Canon Advanced Printing Technology (CAPT) Protocol Dissector
--
-- For use with Wireshark (or any compatible product)
-- Dissects USB traffic to and from select Canon laser printer devices
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
-- NOTE: When opening another log in the Wireshark GUI without restarting,
-- the Segmented Response Journal needs to be cleared to ensure the accuracy
-- of the packet information displayed.
--
-- To manually reset the journal, select Tools -> Clear CAPT Segment Journal
-- and Reload in the WS GUI.
--
-- At least in WS 2.6.6, this limitation is due to the fact that dissector
-- scope variables are not reset when opening another log in the same session.
--

--
-- Main Dissector
--
HOST_PORT = 0xFFFFFFFF  -- USB host in pinfo.dst_port or pinfo.src_port
TYPE_NOT_OPCODE = 0x0
TYPE_IS_OPCODE = 0x01
TYPE_IS_CONTROL = 0x02

-- Segmented Response Packet Journal
local last_spd = {} -- last segmented packet data
local response_headers = {} -- header: frame number->content lookup
local response_pairs = {} -- body<->header: frame number lookup

-- TODO: make protocol names look prettier in WS
capt_proto = Proto("capt", "Canon Advanced Printing Technology")
opcodes_stat = {
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
-- init combined opcodes table (inefficient but acceptable due to small size)
opcodes = {}
for k, v in pairs(opcodes_stat) do opcodes[k] = v end
for k, v in pairs(opcodes_prn) do opcodes[k] = v end

local capt_comment = ProtoField.string("capt.comment", "Comment")
local capt_header_pn = ProtoField.framenum("capt.header_frame", "Response Header in Frame")
local capt_body_pn = ProtoField.framenum("capt.body_frame", "Response Body in Frame")
local capt_cmd = ProtoField.uint16("capt.cmd","Command", base.HEX, opcodes)
local pkt_size = ProtoField.uint16("capt.packet_size", "Packet Size", base.DEC)
local params = ProtoField.new("Parameters", "capt.param_dump", ftypes.BYTES)
	-- PROTIP: ProtoField.new puts name argument first
capt_proto.fields = {
	capt_comment,
	capt_header_pn,
	capt_body_pn,
	capt_cmd,
	pkt_size,
	params,
}

local function capt_opcode_type(opcode)
	if opcodes_prn[opcode] then
		return bit32.bor(TYPE_IS_OPCODE, TYPE_IS_CONTROL)
	elseif opcodes[opcode] then
		return bit32.bor(TYPE_IS_OPCODE)
	end
	return TYPE_NOT_OPCODE
end

function capt_proto.dissector(buffer, pinfo, tree)
	local buffer2 = buffer
	local buflen = buffer2:len()
    local t_pckt = tree:add(capt_proto, buffer2()) --packet details tree heading
	local t_captcmd
	local br_opcode
	local br_size
	local mne
	local opcode
	local optype = TYPE_NOT_OPCODE
	local size

	-- classify...
	-- detect opcode
	if buflen >= 2 then
		br_opcode = buffer2(0, 2)
		opcode = br_opcode:le_uint()
		optype = capt_opcode_type(opcode)
	end

	-- detect segmented response bodies
	if optype == TYPE_NOT_OPCODE then
		local hn = response_pairs[pinfo.number]
		-- pair response body and header on first visit to packet
		if not hn then
			do
				local test = last_spd.number or pinfo.number+1 < pinfo.number
					-- PROTIP: a nil last_spd.number resolves to a number always
					-- higher than pinfo.number as a hack to fail this test
					and last_spd.src_port == pinfo.src_port
					and last_spd.dst_port == pinfo.dst_port
				if test then
					response_pairs[pinfo.number] = last_spd.number
					-- response_pairs[last_spd.number] = pinfo.number
					-- TODO: Find out why back-linking doesn't work
					last_spd = {} -- reset to prevent spurious pairings
					return
				else
					-- no last known header: assume unknown opcode
					pinfo.cols.protocol:set("CAPT")
					pinfo.cols.info:set(string.format("Unknown opcode %x", opcode))
					t_captcmd = t_pckt:add(capt_comment, string.format("???"))
					return
				end
			end
		else
			-- attempt to reassemble packet if 'matching' header found
			do
				local hbytes = response_headers[hn]
				local rabytes = ByteArray.new()
				rabytes:append(hbytes)
				rabytes:append(buffer2:bytes())
				-- switch buffers, re-detect opcode and size
				buffer2 = rabytes:tvb('Response')
				br_opcode = buffer2(0, 2)
				br_size = buffer2(2, 2)
				size = br_size:le_uint()
				opcode = br_opcode:le_uint()
				optype = capt_opcode_type(opcode)
				t_captcmd = t_pckt:add(capt_header_pn, hn)
				t_captcmd:add_le(capt_cmd, br_opcode)
			end
		end
	elseif buflen >= 4 then
		-- handle packets with header
		br_size = buffer2(2, 2)
		size = br_size:le_uint()
		if bit32.btest(optype, TYPE_IS_OPCODE) then
			-- save headers of segmented packets on first visit
			if size > buflen then
				local pn = pinfo.number
				if not response_headers[pn] then
					last_spd.number = pn
					last_spd.src_port = pinfo.src_port
					last_spd.dst_port = pinfo.dst_port
					response_headers[pn] = buffer2:bytes()
				end
			end
			t_captcmd = t_pckt:add_le(capt_cmd, br_opcode)
			t_captcmd:add_le(pkt_size, br_size)
		end
	end

	mne = opcodes_prn[opcode] or opcodes[opcode]
	if bit32.btest(optype, TYPE_IS_CONTROL) then
		pinfo.cols.protocol = "CAPT Control"
		pinfo.cols.info:append(string.format(" %s ", mne))
	else
		pinfo.cols.protocol = "CAPT Status"
		pinfo.cols.info:set(mne)
		if pinfo.dst_port ~= HOST_PORT then
			pinfo.cols.info:append(" (send command)")
		end
	end

	-- dissect!
	if opcode == 0xD0A9 then
		-- multi-command packet
		pinfo.cols.info:set(string.format("%s:", mne))
		local i = 4
		while i < size do
			local n = buffer2(i+2, 2):le_uint()
			local gr_opcode = buffer2(i, 2):le_uint()
			local gr_mne = opcodes_prn[gr_opcode]
			local t_gcmd = t_captcmd:add_le(capt_cmd, buffer2(i, 2))
			capt_proto.dissector(buffer2(i, n):tvb(), pinfo, t_gcmd)
			i = i + n -- is there a Lua increment operator?
		end
	elseif size > 4 then
		-- single-command packet
		if size > buffer2:len() then
			do
				local rn = response_pairs[pinfo.number]
				if rn then
					t_captcmd:add(capt_body_pn, rn)
				else
					t_captcmd:add(capt_comment, "See next Response Body from this source to host for remaining data")
				end
				pinfo.cols.info:append(" (recv header)")
			end
		else
			local n = size - 4
			local br_parm = buffer2(4, n)
			t_captcmd:add(params, br_parm)
			-- select sub-dissector
			if opcode == 0xA0A1 or opcode == 0xA0A8 or opcode == 0xE0A0 then
				capt_stat_proto.dissector(br_parm:tvb(), pinfo, t_captcmd)
			elseif opcode == 0xA1A1 then
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

-- 0xA0A1, 0xA0A8, 0xE0A0: Status Checks
-- Just dump all bytes into the information column
capt_stat_proto = Proto("capt_status", "CAPT Status")
function capt_stat_proto.dissector(buffer, pinfo, tree) do
	local dumphex = buffer(0,-1):bytes():tohex(false, ' ')
	pinfo.cols.info:append(string.format(": %s", dumphex))
end end

-- 0xA1A1: CAPT_IDENT
-- Device automagic configuration data, perhaps for use with the Axis 1650
-- network adapter and the NetSpot Installer software.
--
-- Note: The paper specs appear to be in 1/10ths mm, apparently for fixed
-- point arithmetic (to avoid floats when HF is not available)
local prefix = "capt_ident"
local a1a1_mag_color = ProtoField.uint16(prefix .. ".magic_color", "Color Printing(?)")
local a1a1_mag_product = ProtoField.uint16(prefix .. ".magic_product", "Product Code(?)")
local a1a1_mag_c = ProtoField.uint16(prefix .. ".magic_c", "Magic Number C")
local a1a1_mag_d = ProtoField.uint16(prefix .. ".magic_feature_bm_a", "Feature Bitmask A(?)",base.HEX)
local a1a1_throughput = ProtoField.uint16(prefix .. ".throughput", "Throughput/Maximum Print Speed (pages/hr)")
local a1a1_w_max = ProtoField.uint16(prefix .. ".w_max", "Maximum Paper Width (x0.1 mm)")
local a1a1_w_min = ProtoField.uint16(prefix .. ".w_min", "Minimum Paper Width (x0.1 mm)")
local a1a1_h_max = ProtoField.uint16(prefix .. ".h_max", "Maximum Paper Height (x0.1 mm)")
local a1a1_h_min = ProtoField.uint16(prefix .. ".h_min", "Minimum Paper Height (x0.1 mm)")
local a1a1_npt = ProtoField.uint8(prefix .. ".npt", "Top Non-printable Margin (x0.1mm)")
local a1a1_npb = ProtoField.uint8(prefix .. ".npb", "Bottom Non-printable Margin(x0.1 mm)")
local a1a1_npl = ProtoField.uint8(prefix .. ".npl", "Left Non-printable Margin(x0.1 mm)")
local a1a1_npr = ProtoField.uint8(prefix .. ".npr", "Right Non-printable Margin (x0.1 mm)")
local a1a1_rx = ProtoField.uint16(prefix .. ".rx", "X Resolution(?)")
local a1a1_ry = ProtoField.uint16(prefix .. ".ry", "Y Resolution(?)")
local a1a1_mag_capt_ver = ProtoField.uint16(prefix .. ".magic_capt_ver", "CAPT Version")
a1a1_proto = Proto(prefix, "CAPT: Printer Information")
a1a1_proto.fields = {
	a1a1_mag_color,
	a1a1_mag_product,
	a1a1_mag_c,
	a1a1_mag_d,
	a1a1_throughput,
	a1a1_w_max,
	a1a1_h_max,
	a1a1_w_min,
	a1a1_h_min,
	a1a1_npt,
	a1a1_npb,
	a1a1_npl,
	a1a1_npr,
	a1a1_rx,
	a1a1_ry,
	a1a1_mag_capt_ver,
}
function a1a1_proto.dissector(buffer, pinfo, tree)
	tree:add_le(a1a1_mag_color, buffer(0,2))
	tree:add_le(a1a1_mag_product, buffer(2,1))
	tree:add_le(a1a1_mag_c, buffer(4,2))
	tree:add_le(a1a1_mag_d, buffer(6,2))
	tree:add_le(a1a1_throughput, buffer(16,2))
	tree:add_le(a1a1_w_max, buffer(20,2))
	tree:add_le(a1a1_h_max, buffer(24,2))
	tree:add_le(a1a1_w_min, buffer(32,2))
	tree:add_le(a1a1_h_min, buffer(36,2))
	tree:add_le(a1a1_npt, buffer(40,1))
	tree:add_le(a1a1_npb, buffer(41,1))
	tree:add_le(a1a1_npl, buffer(42,1))
	tree:add_le(a1a1_npr, buffer(43,1))
	tree:add_le(a1a1_rx, buffer(44,2))
	tree:add_le(a1a1_ry, buffer(46,2))
	tree:add_le(a1a1_mag_capt_ver, buffer(48,1))
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

-- dissector registration
local dt_usb_product = DissectorTable.get("usb.product")
dt_usb_product:add(0x04a9260a, capt_proto) -- LBP810
dt_usb_product:add(0x04a92676, capt_proto) -- LBP2900
dt_usb_product:add(0x04a9266a, capt_proto) -- LBP3000
dt_usb_product:add(0x04a926da, capt_proto) -- LBP3010/3018/3050
dt_usb_product:add(0x04a926db, capt_proto) -- LBP3100/3108/3150
dt_usb_product:add(0x04a926b9, capt_proto) -- LBP3310
--dt_usb_product:add(YOUR_DEVICE_NUMBER, capt_proto)

-- PROTIP: If the number for your device is missing from above, you may
-- need to add it here to use this dissector.
-- If on Linux or BSD, obtain your number from running the lsusb command.
-- Copy the ID, remove the colon and add '0x' in front of it.

-- Using macOS? Try System Report in About This Mac. Goto Hardware > USB,
-- and find your device there... Combine your vendor ID and device ID
-- (in that order) into one 8-digit hex number, add the 0x in front.

-- You can also remove any devices that you don't have or are not using.

local dt_usb = DissectorTable.get("usb.bulk")
dt_usb:add(0x0, capt_proto)
dt_usb:add(0xff, capt_proto)
dt_usb:add(0xffff, capt_proto)

-- Helper Functions, Listeners, etc...
local function clear_journal()
	last_spd = {}
	response_headers = {}
	response_pairs = {}
	if gui_enabled() then
		reload_packets()
	end
end

register_menu("Clear CAPT Segment Journal and _Reload", clear_journal, MENU_TOOLS_UNSORTED)
