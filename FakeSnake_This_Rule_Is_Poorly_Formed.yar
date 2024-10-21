// Detection Rule License (DRL) 1.1
// https://github.com/Neo23x0/signature-base/blob/master/LICENSE

rule This_Rule_Is_Malformed
{
	meta:
		x_timestamp = "1683676800000"
		name = "Demo Rule - Poorly formed, for demo only"
		author = "Modified by Marty for demo purposes"
		description = "Detects a series of strings"
		date = "2024-10-17"
		tlp = "clear"
		x_threat_name = "MartyTheOTGuy"
		x_mitre_technique = "T1570, T1106, T1569.002 T1040, T0840, T1071.001"
		hash1 = "3F3F48898928B09155D6DFC11BA1694D"

	strings:
		$a = { 25 73 23 31 }
		$b = { 25 73 23 32 }
		$c = { 25 73 23 33 }
		$d = { 25 73 23 34 }
		$e = { 2e 74 6d 70 }
		$g = { 2e 73 61 76 }
		$h = { 2e 75 70 64 }

	condition:
		all of them
}