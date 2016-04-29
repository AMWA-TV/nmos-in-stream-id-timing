-- Wireshark Lua Dissector for NMOS Header Extensions
-- Author: Stuart Grace (stuart.grace@bbc.co.uk)
--
-- To use in Wireshark:
-- 1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua
-- 2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
--    and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
--    should list "nmos_hdrexts.lua" 
-- 3) In Wireshark Preferences, under "Protocols", find RTP_NMOS_HDREXTS and set the header extension IDs
--    according to the values listed in the source's SDP file (lines beginning "a=extmap:")
-- 4) Capture packets of an RTP stream
-- 5) "Decode As..." the UDP packets as RTP
-- 6) On a packet with header extensions (e.g. first packet of each grain), you will now see each RFC5285 header
--    extension labelled with its purpose (e.g. Sync Timestamp) and value
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
------------------------------------------------------------------------------------------------  
do  
    local rtp_nmos_hdrexts  = Proto("rtp_nmos_hdrexts", "NMOS Hdr Exts")

    local rtp_nmos_syncts   = Proto("rtp_nmos_syncts", "NMOS Sync Timestamp")
    local rtp_nmos_origints = Proto("rtp_nmos_origints", "NMOS Origin Timestamp")
    local rtp_nmos_timecode = Proto("rtp_nmos_timecode", "NMOS SMPTE 12M Timecode")
    local rtp_nmos_flowid   = Proto("rtp_nmos_flowid", "NMOS Flow ID")
    local rtp_nmos_sourceid = Proto("rtp_nmos_sourceid", "NMOS Source ID")
    local rtp_nmos_graindur = Proto("rtp_nmos_graindur", "NMOS Grain Duration")
    local rtp_nmos_grainflg = Proto("rtp_nmos_grainflg", "NMOS Grain Flags")

    -- Settings on the Preferences dialog
    local prefs = rtp_nmos_hdrexts.prefs
    prefs.sync_ts   = Pref.uint("Header extension id for carrying Sync Timestamp (1-14)", 7, "Valid range is 1 to 14")
    prefs.origin_ts = Pref.uint("Header extension id for carrying Origin Timestamp (1-14)", 1, "Valid range is 1 to 14")
    prefs.timecode  = Pref.uint("Header extension id for carrying SMPTE 12M Timecode (1-14)", 2, "Valid range is 1 to 14")
    prefs.flow_id   = Pref.uint("Header extension id for carrying Flow ID (1-14)", 3, "Valid range is 1 to 14")
    prefs.source_id = Pref.uint("Header extension id for carrying Source ID (1-14)", 4, "Valid range is 1 to 14")
    prefs.grain_dur = Pref.uint("Header extension id for carrying Grain Duration (1-14)", 9, "Valid range is 1 to 14")
    prefs.grain_flg = Pref.uint("Header extension id for carrying Grain Flags (1-14)", 5, "Valid range is 1 to 14")

    -- Fields that can be displayed in the packet details
    local SyncTSFields = rtp_nmos_syncts.fields
    SyncTSFields.SyncTS = ProtoField.string("rtp_nmos_hdrexts.sync_ts","NMOS Sync Timestamp (TAI time scale)")
    SyncTSFields.Err    = ProtoField.string("rtp_nmos_hdrexts.sync_ts_error",
        "ERROR: NMOS Sync Timestamp should have length 10. Check header id values in Preferences -> Protocols")

    local OriginTSFields = rtp_nmos_origints.fields
    OriginTSFields.OriginTS = ProtoField.string("rtp_nmos_hdrexts.origin_ts","NMOS Origin Timestamp (TAI time scale)")
    OriginTSFields.Err      = ProtoField.string("rtp_nmos_hdrexts.origin_ts_error",
        "ERROR: NMOS Origin Timestamp should have length 10. Check header id values in Preferences -> Protocols")

    local TimecodeFields = rtp_nmos_timecode.fields
    TimecodeFields.FramesU = ProtoField.uint32("rtp_nmos_hdrexts.timecode.framesunits","SMPTE Timecode Frames (units)",
                               base.HEX, nil, 0xFF000000)
    TimecodeFields.FramesT = ProtoField.uint32("rtp_nmos_hdrexts.timecode.framestens","SMPTE Timecode Frames (tens)",
                               base.HEX, nil, 0x00FF0000)
    TimecodeFields.SecsU = ProtoField.uint32("rtp_nmos_hdrexts.timecode.secsunits","SMPTE Timecode Seconds (units)",
                               base.HEX, nil, 0x0000FF00)
    TimecodeFields.SecsT = ProtoField.uint32("rtp_nmos_hdrexts.timecode.secstens","SMPTE Timecode Seconds (tens)",
                               base.HEX, nil, 0x000000FF)
    TimecodeFields.MinsU = ProtoField.uint32("rtp_nmos_hdrexts.timecode.framesunits","SMPTE Timecode Minutes (units)",
                               base.HEX, nil, 0xFF000000)
    TimecodeFields.MinsT = ProtoField.uint32("rtp_nmos_hdrexts.timecode.framestens","SMPTE Timecode Minutes (tens)",
                               base.HEX, nil, 0x00FF0000)
    TimecodeFields.HoursU = ProtoField.uint32("rtp_nmos_hdrexts.timecode.secsunits","SMPTE Timecode Hours (units)",
                               base.HEX, nil, 0x0000FF00)
    TimecodeFields.HoursT = ProtoField.uint32("rtp_nmos_hdrexts.timecode.secstens","SMPTE Timecode Hours (tens)",
                               base.HEX, nil, 0x000000FF)
    TimecodeFields.Err    = ProtoField.string("rtp_nmos_hdrexts.timecode_error",
        "ERROR: NMOS SMPTE Timecode should have length 8. Check header id values in Preferences -> Protocols")

    local FlowIDFields = rtp_nmos_flowid.fields
    FlowIDFields.FlowID = ProtoField.string("rtp_nmos_hdrexts.flow_id","NMOS Flow ID")
    FlowIDFields.Err    = ProtoField.string("rtp_nmos_hdrexts.flow_id_error",
        "ERROR: NMOS Flow ID should have length 16. Check header id values in Preferences -> Protocols")

    local SourceIDFields = rtp_nmos_sourceid.fields
    SourceIDFields.SourceID = ProtoField.string("rtp_nmos_hdrexts.source_id","NMOS Source ID")
    SourceIDFields.Err      = ProtoField.string("rtp_nmos_hdrexts.source_id_error",
        "ERROR: NMOS Source ID should have length 16. Check header id values in Preferences -> Protocols")

    local GrainDurFields = rtp_nmos_graindur.fields
    GrainDurFields.GrainDur = ProtoField.string("rtp_nmos_hdrexts.grain_dur","NMOS Grain Duration")
    GrainDurFields.Err      = ProtoField.string("rtp_nmos_hdrexts.grain_dur_error",
        "ERROR: NMOS Grain Duration should have length 8. Check header id values in Preferences -> Protocols")

    local GrainFlagFields = rtp_nmos_grainflg.fields
    GrainFlagFields.Start = ProtoField.uint8("rtp_nmos_hdrexts.flags.start", "NMOS Start of grain",
                               base.DEC, {[0]="False", [1]="True"}, 0x80)
    GrainFlagFields.End   = ProtoField.uint8("rtp_nmos_hdrexts.flags.end", "NMOS End of grain",
                               base.DEC, {[0]="False", [1]="True"}, 0x40)
    GrainFlagFields.Resd  = ProtoField.uint8("rtp_nmos_hdrexts.flags.reserved", "NMOS Reserved",
                               base.HEX, nil, 0x3F)
    GrainFlagFields.Err   = ProtoField.string("rtp_nmos_hdrexts.flags.error",
        "ERROR: NMOS Grain Flags should have length 1. Check header id values in Preferences -> Protocols")

    function rtp_nmos_syncts.dissector(tvb, pinfo, tree)
        if (tvb:reported_len() == 10) then
            -- Timestamp has 48 bits for seconds and 32 bits for nanoseconds since 1970-01-01 00:00
            -- Value uses TAI time scale which does not include leap seconds and is therefore
            -- a number of seconds ahead of UTC (36 seconds ahead in Jan 2016).
            local secs = (tvb:range(0,4):uint()*65536)+tvb:range(4,2):uint()
            local nanos = tvb:range(6,4):uint()
            local fmtd = string.format("%d.%09d (%s)", secs, nanos, os.date("%c",secs))
            tree:add(SyncTSFields.SyncTS, fmtd)
        else
            tree:add(SyncTSFields.Err)
            tree:add_expert_info(PI_PROTOCOL, PI_WARN)
        end
    end

    function rtp_nmos_origints.dissector(tvb, pinfo, tree)
        if (tvb:reported_len() == 10) then
            -- Timestamp has 48 bits for seconds and 32 bits for nanoseconds since 1970-01-01 00:00
            -- Value uses TAI time scale which does not include leap seconds and is therefore
            -- a number of seconds ahead of UTC (36 seconds ahead in Jan 2016).
            local secs = (tvb:range(0,4):uint()*65536)+tvb:range(4,2):uint()
            local nanos = tvb:range(6,4):uint()
            local fmtd = string.format("%d.%09d (%s)", secs, nanos, os.date("%c",secs))
            tree:add(OriginTSFields.OriginTS, fmtd)
        else
            tree:add(OriginTSFields.Err)
            tree:add_expert_info(PI_PROTOCOL, PI_WARN)
        end
    end

    function rtp_nmos_timecode.dissector(tvb, pinfo, tree)
        if (tvb:reported_len() == 8) then
            tree:add(TimecodeFields.FramesU, tvb:range(0,4):uint())
            tree:add(TimecodeFields.FramesT, tvb:range(0,4):uint())
            tree:add(TimecodeFields.SecsU, tvb:range(0,4):uint())
            tree:add(TimecodeFields.SecsT, tvb:range(0,4):uint())
            tree:add(TimecodeFields.MinsU, tvb:range(4,4):uint())
            tree:add(TimecodeFields.MinsT, tvb:range(4,4):uint())
            tree:add(TimecodeFields.HoursU, tvb:range(4,4):uint())
            tree:add(TimecodeFields.HoursT, tvb:range(4,4):uint())
        else
            tree:add(TimecodeFields.Err)
            tree:add_expert_info(PI_PROTOCOL, PI_WARN)
        end
    end

    function rtp_nmos_flowid.dissector(tvb, pinfo, tree)
        if (tvb:reported_len() == 16) then
            local fmtd = string.format("%08x-%04x-%04x-%04x-%08x%04x",
                     tvb:range(0,4):uint(), tvb:range(4,2):uint(),
                     tvb:range(6,2):uint(), tvb:range(8,2):uint(),
                     tvb:range(10,4):uint(), tvb:range(14,2):uint())
            tree:add(FlowIDFields.FlowID, fmtd)
        else
            tree:add(FlowIDFields.Err)
            tree:add_expert_info(PI_PROTOCOL, PI_WARN)
        end
    end

    function rtp_nmos_sourceid.dissector(tvb, pinfo, tree)
        if (tvb:reported_len() == 16) then
            local fmtd = string.format("%08x-%04x-%04x-%04x-%08x%04x",
                     tvb:range(0,4):uint(), tvb:range(4,2):uint(),
                     tvb:range(6,2):uint(), tvb:range(8,2):uint(),
                     tvb:range(10,4):uint(), tvb:range(14,2):uint())
            tree:add(SourceIDFields.SourceID, fmtd)
        else
            tree:add(SourceIDFields.Err)
            tree:add_expert_info(PI_PROTOCOL, PI_WARN)
        end
    end

    function rtp_nmos_graindur.dissector(tvb, pinfo, tree)
        if (tvb:reported_len() == 8) then
            local num = tvb:range(0,4):uint()
            local den = tvb:range(4,4):uint()
            local fmtd = string.format("%d/%d s (%g ms)", num, den, (1000*num)/den)
            tree:add(GrainDurFields.GrainDur, fmtd)
        else
            tree:add(GrainDurFields.Err)
            tree:add_expert_info(PI_PROTOCOL, PI_WARN)
        end
    end

    function rtp_nmos_grainflg.dissector(tvb, pinfo, tree)
        if (tvb:reported_len() == 1) then
            tree:add(GrainFlagFields.Start, tvb:range(0):uint())
            tree:add(GrainFlagFields.End, tvb:range(0):uint())
            tree:add(GrainFlagFields.Resd, tvb:range(0):uint())
        else
            tree:add(GrainFlagFields.Err)
            tree:add_expert_info(PI_PROTOCOL, PI_WARN)
        end
    end

    -- register dissectors in RFC5285 header extension type table
    local ext_profile_table = DissectorTable.get("rtp.ext.rfc5285.id")

    function rtp_nmos_hdrexts.init()  
      ext_profile_table:add(prefs.sync_ts, rtp_nmos_syncts.dissector)
      ext_profile_table:add(prefs.origin_ts, rtp_nmos_origints.dissector)
      ext_profile_table:add(prefs.timecode, rtp_nmos_timecode.dissector)
      ext_profile_table:add(prefs.flow_id, rtp_nmos_flowid.dissector)
      ext_profile_table:add(prefs.source_id, rtp_nmos_sourceid.dissector)
      ext_profile_table:add(prefs.grain_dur, rtp_nmos_graindur.dissector)
      ext_profile_table:add(prefs.grain_flg, rtp_nmos_grainflg.dissector)
    end  
end

