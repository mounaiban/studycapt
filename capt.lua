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

-- NOTE: this dissector is still only able to dissect the initial packets
-- in a command response. Follow-up response packets (containing data after
-- the 6th byte) and constituent commands sent by CAPT_SET_PARMS are is still
-- not dissected.

--
-- Main Dissectors
--

-- Selection Heuristic
--
-- This classifies packets by the first two bytes of the USB bulk transfer
-- payload. If a known CAPT opcode is detected, a suitable dissector is
-- selected.
local function detect_capt(buffer, pinfo, tree)
	if buffer:len() < 4 then return false end -- no command is shorter than 4B
	cmd_bytes = buffer(0,2):le_uint()
	if opcodes[cmd_bytes] then
		pinfo.cols['protocol'] = 'CAPT Status Monitor'
		captstatus_proto.dissector(buffer, pinfo, tree)
		return true
	elseif opcodes_prn[cmd_bytes] then
		pinfo.cols['info']:clear()
		pinfo.cols['protocol'] = 'CAPT Device Control'
		captstatus_prn_proto.dissector(buffer, pinfo, tree)
		return true
	else return false end
end

-- TODO: make protocol names look prettier in WS

-- Status Monitor Main Dissector
captstatus_proto = Proto("capt_status", "Canon Advanced Printing Technology Status Monitor")
opcodes = {
    [0xA0A1] = "CAPT_CHKJOBSTAT",
    [0xA0A8] = "CAPT_XSTATUS",
    [0xA1A0] = "CAPT_IEEE_IDENT",
    [0xA1A1] = "CAPT_IDENT",
    [0xE0A0] = "CAPT_CHKSTATUS",
}
local stat_p_size = ProtoField.uint16("capt_status.p_size", "Packet Size", base.DEC)
local capt_stat_cmd = ProtoField.uint16("capt_status.cmd","Command", base.HEX, opcodes)
captstatus_proto.fields = {capt_stat_cmd, stat_p_size}

function captstatus_proto.dissector(buffer, pinfo, tree)
    local t_captstatus = tree:add(captstatus_proto, buffer())
	local br_opcode = buffer(0, 2)
    t_captstatus:add_le(capt_stat_cmd, br_opcode)
	pinfo.cols['info'] = opcodes[br_opcode:le_uint()]
    t_captstatus:add_le(stat_p_size, buffer(2, 2))
end

-- Device Control Main Dissector
captstatus_prn_proto = Proto("capt_prn", "Canon Advanced Printing Technology Device Control")
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
	[0xE0A7] = "CAPT_FIRE", -- start actual printing process for page?
	[0xE0A9] = "CAPT_JOB_END",
	[0xE1A1] = "CAPT_JOB_SETUP",
	[0xE1A2] = "CAPT_GPIO",
}
local capt_prn_cmd = ProtoField.uint16("capt_prn.cmd","Command", base.HEX, opcodes_prn)
local prn_p_size = ProtoField.uint16("capt_prn.p_size", "Packet Size", base.DEC)
local params = ProtoField.new("Parameters", "capt_prn.params", ftypes.BYTES)
	-- PROTIP: ProtoField.new puts name argument first
local gr_cmd = ProtoField.string("capt_prn.group", "Grouped Command") -- TODO: change to capt_prn.gcmd
captstatus_prn_proto.fields = {capt_prn_cmd, prn_p_size, params, gr_cmd}

function captstatus_prn_proto.dissector(buffer, pinfo, tree)
    local t_pckt = tree:add(captstatus_prn_proto, buffer()) -- heading
	local br_opcode = buffer(0, 2)
	local opcode = br_opcode:le_uint()
	local mne = opcodes_prn[opcode]
	local size = buffer(2, 2):le_uint()
    local t_captcmd = t_pckt:add_le(capt_prn_cmd, br_opcode)
    t_captcmd:add_le(prn_p_size, buffer(2, 2))
	pinfo.cols['info']:append(mne .. ' ')
	if mne == "CAPT_SET_PARMS" then -- TODO: change to opcode check for consistency
		-- dissect multi-command packet
		local i = 4
		while i < size do
			local n = buffer(i+2, 2):le_uint()
			local gr_op_num = buffer(i, 2):le_uint()
			local gr_mne = opcodes_prn[gr_op_num]
			local gr_op_mne = string.format("%s (0x%x)", gr_mne, gr_op_num)
			local t_grcmd = t_captcmd:add(gr_cmd, buffer(i, n), gr_op_mne)
			captstatus_prn_proto.dissector(buffer(i, n):tvb(), pinfo, t_grcmd)
			i = i + n -- is there a Lua increment operator?
		end
	elseif size > 4 then
		local n = size - 4
		local br_parm = buffer(4, n)
		t_captcmd:add(params, br_parm)
		-- select sub-dissector
		if opcode == 0xD0A0 then
			d0a0_proto.dissector(br_parm:tvb(), pinfo, t_captcmd)
		elseif opcode == 0xE1A1 then
			e1a1_proto.dissector(br_parm:tvb(), pinfo, t_captcmd)
		end
	end
end

--
-- Device Control Sub-Dissectors
--

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

-- E1A1: CAPT_JOB_SETUP
-- NOTE: the name is a bit of a misnomer as this command doesn't set up
-- a job, but it tells the printer which job it is at, and at what stage
local prefix = 'capt_job_setup'
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
end

--
captstatus_proto:register_heuristic("usb.bulk", detect_capt)
