rule Malware
{
    meta:
        description = "This is a yara rules based on the unknown malware analysis"
    strings:
        $pe = "MZ"
        $b = "PSUT.dll is missing!" wide
        $c = "C:\\windows\\updator.exe" wide
        $d= "CaesarCipher" ascii
        $e ="C:\\Users\\Hacked.txt"wide
        $f= "http://www.example.com/post_handler" wide
        $g ="SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True" wide

    condition:
        ($pe at 0 and ($b or $c)) or ( ($pe at 0 and ($d and $e)) or ($f or $g) )
}
