# Wireshark Plugin for NMOS Header Extensions

## Requirements
This plugin is written in Lua. To check if your version of Wireshark supports Lua plugins, go to Help, About Wireshark, and check that it
says it was compiled with Lua.

## Installation
* Note the location of Wireshark's personal or global plugin directory shown at Help, About Wireshark, Folders tab.
* Copy the file nmos_hdrexts.lua into this directory and restart Wireshark.
* Check that Help, About Wireshark, Plugins tab shows nmos_hdrexts.lua in the list.

## Configuration
In Edit, Preferences, Protocols, find RTP_NMOS_HDREXTS. Here you set the header extension IDs (as defined in RFC 5285) according to the values listed in the sender's SDP file (on lines beginning "a=extmap:"). For example, if the senders SDP file includes the line

    a=extmap:3 urn:x-nmos:rtp-hdrext:flow-id

you should set the value "Header extension id for carrying Flow ID (1-14)" to 3.

## Operation
* Capture some packets from an RTP stream.
* Select "Decode As..." for one of the UDP packets and select RTP as the protocol.
* On any packet with header extensions (e.g. first packet of each grain), you will now see each RFC5285 header extension labelled with its purpose (e.g. Sync Timestamp) and value.

## Notes
* Sync and Origin timestamps use the TAI time scale which does not include leap seconds. They will therefore be a number of seconds ahead of UTC. The difference is 36 seconds at Jan 2016 but may increase.
* SMPTE 12M Timecode can carry additional user data in the high order bits of each byte, as well as the timecode values in the low order bits.

