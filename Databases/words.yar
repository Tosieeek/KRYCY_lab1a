rule Suspicious_words {
    strings: $a = "malware" nocase
             $b = "wirus" nocase
             $c = "politechnika" nocase
             $d = "wannacry" nocase
             $e = "stuxnet" nocase
    condition: any of them
}