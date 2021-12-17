rule Suspicious_number_of_ips {
    strings:
        $a = { 31 33 32 2e 31 32 31 2e 32 33 33 2e ?? ?? ?? } // 132.121.233.[0-255]
        $b = { 31 35 31 2e 31 30 31 2e 31 2e 36 39 }  // 151.101.1.69
    condition: #a > 1 or #b > 1

}