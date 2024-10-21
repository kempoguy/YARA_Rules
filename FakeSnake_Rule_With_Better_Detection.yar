// Detection Rule License (DRL) 1.1
// https://github.com/Neo23x0/signature-base/blob/master/LICENSE

rule Rule_With_Better_Detection_Marty_The_OT_Guy
{
	meta:
		x_timestamp = "1683676800000"
		name = "Demo Rule - PE and File Size"
		author = "Marty The OT Guy"
		description = "Detects using Magic Byte and File Size"
		date = "2023-05-10"
		tlp = "clear"
		x_threat_name = "MartyTheOTGuy"


	strings:
		$a = { 25 73 23 31 }
		$b = { 25 73 23 32 }
		$c = { 25 73 23 33 }
		$d = { 25 73 23 34 }
		$e = { 2e 74 6d 70 }
		$g = { 2e 73 61 76 }
		$h = { 2e 75 70 64 }

	condition:
		uint16(0) == 0x5A4D and
		filesize < 5MB and
		all of them
}