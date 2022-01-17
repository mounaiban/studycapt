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
-- Dissector Selection Heuristic
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

--
-- Status Monitor Dissector Setup
--
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

--
-- Device Control Dissector Setup
--
captstatus_prn_proto = Proto("capt_prn", "Canon Advanced Printing Technology Device Control") -- TODO: make the name look prettier in WS
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
local gr_cmd = ProtoField.string("capt_prn.group", "Grouped Command")
captstatus_prn_proto.fields = {capt_prn_cmd, prn_p_size, params, gr_cmd}

function captstatus_prn_proto.dissector(buffer, pinfo, tree)
    local t_pckt = tree:add(captstatus_prn_proto, buffer())
	local br_opcode = buffer(0, 2)
	local mne = opcodes_prn[br_opcode:le_uint()]
	local size = buffer(2, 2):le_uint()
    local t_captcmd = t_pckt:add_le(capt_prn_cmd, br_opcode)
    t_captcmd:add_le(prn_p_size, buffer(2, 2))
	pinfo.cols['info']:append(mne .. ' ')
	if mne == "CAPT_SET_PARMS" then
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
	else
		if size > 4 then
			t_captcmd:add(params, buffer(4, size-4))
		end
	end
end

--
captstatus_proto:register_heuristic("usb.bulk", detect_capt)
