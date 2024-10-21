Contents:

These files are for demo purposes only. 
They show the difference between a loosely defined Yara rule and one which has better definition and detection. 
The binary files are fake files edited to trigger these rules deliberately.

* Fakesnake.exe - a fake executable that will trigger the Yara rules in this repo. For demo only. Will trigger some real APT Turla Uroborus Yara rules.
* Fakesnake_This_Rule_Is_Poorly_Formed.yar - Yara rule that will trigger from fakesnake and File1.bin, but not File2.bin
* Fakesnake_Rule_With_Better_Detection.yar - Yara rule that will trigger from fakesnake and File2.bin, but not File1.bin
* File1.bin - File containing strings to trigger the poorly formed Yara rule. Has no PE magic bytes.
* File2.bin - File containing strings and PE magic bytes to trigger proper Yara rule. Will not trigger poorly formed rule. Will trigger some real APT Turla Uroborus Yara rules.



****************************************************************************************************************************************************
Copywrong 2024 Marty The OT Guy - no warranty, liability, sanity, comedy or anything else offered, implied, accepted, folded, spindled or mutilated.
****************************************************************************************************************************************************