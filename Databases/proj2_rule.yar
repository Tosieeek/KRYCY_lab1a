rule malware_signatures {
    strings:
        $malware_part1 = { 2D D3 AF C5 30 F0 8A 05 D8 9E 12 50 88 BA 92 FD 1F 94 21 05 7F 93 F5 69 14 EE 3B BD 2D E8 0E 5B B9 80 FB 6F 4A 50 DC 4F 4D 3E B3 A8 C6 93 15 5B C4 A9 BB 98 37 }
        $malware_part2 = { 3F C7 57 27 72 3C B2 A5 70 6C AD 94 C3 7F 84 35 F1 81 15 E5 FE A9 65 A1 ED EB 26 4F 54 60 2A 55 33 DD A3 F3 82 1A 16 84 BC DD 0E 3E D0 F1 E1 BF 4D EC 0A CE 9A CB 59 4D 60 1B }
        $malware_part3 = { 44 7F B5 8D 94 4A 81 E5 05 0A 6A 55 65 5C 20 54 8F EE A3 DE C4 66 E8 5B 09 9A 6E 7F 04 C6 43 6E 3D 78 09 D5 55 AE 10 68 29 3F BC B0 3D 94 59 50 62 0A 11 05 14 BC C7 AD 6A 0F B4 B7 AA 75 FB A2 95 B9 18 08 EA AF 5B 51 18 58 7E 42 E6 }
        $malware_part4 = { 39 D3 14 29 F6 9F 9D E6 89 3F 5A B9 9F 69 9B A3 F6 91 B7 8E 80 97 94 5C D2 37 BF EB 45 96 40 A6 84 3F 48 DD A6 9C 40 78 11 7C 3D D7 AF 31 4F C4 F1 CA 3C 1A AE 4E 16 FB E1 59 02 }

    condition: $malware_part1 and $malware_part2 and $malware_part3 and $malware_part4
}

rule parameters {
    strings:
        $get = /\/[0-9a-zA-Z]{1,32}\/get.php/ nocase
        $process = /\/[0-9a-zA-Z]{1,32}\/process.php/ nocase
        $news = "/news.php" nocase
        $response = "404 - File or directory not found" nocase
        $php = /GET [0-9a-zA-Z\/]{1,32}.php/ nocase

    condition: #get + #process + #news > 10 or #response > 14 or #php > 30
}

rule launcher {
    strings:
        $launcher_command = { 57 69 6e 64 6f 77 73 50 6f 77 65 72 53 68 65 6C 6C 5C 76 31 2E 30 5C 70 6F 77 65 72 73 68 65 6C 6C 2E 65 78 65 22 20 2D 6E 6F 6C 20 2D 6E 6F 70 20 2D 65 70 20 62 79 70 61 73 73 20 22 5B 49 4F 2E 46 69 }

    condition: $launcher_command
}

rule admin_php {
    strings:
        $admin_php_part1 = { FA 91 DE 5E 52 42 C2 5F AF 2E 9F 78 8F AB E1 C6 77 84 16 25 BA 26 31 97 96 70 B7 9F AF C3 A8 66 7C 3A 14 13 88 02 36 7F 19 55 13 5B 18 5F 58 FF 89 F0 09 FE 4B 74 33 F3 F0 }
        $admin_php_part2 = { B6 F2 E2 6B 0C 7F E3 34 09 5A EE 83 2B FD D3 AB 41 DE 3D 89 8F 74 38 6A 36 F4 17 F4 51 2E 5E B1 7E E0 A9 9A 95 70 73 02 66 C5 26 80 08 77 C5 59 40 15 C3 11 7B E7 B6 8F 7D }
        $admin_php_part3 = { 28 D9 81 33 7F D9 47 E6 C6 96 7F AF E4 A0 1F D0 9E DE 9B 8C 88 F5 05 E2 88 3F 65 D1 07 6F 02 E2 0E FD 73 1E 62 C2 C6 7A 82 57 2F B7 3C 73 FC 55 DC 49 E9 19 3A CD D1 B1 D7 6A 2F FA FC 05 4B 0C 8B ED B5 }
    condition: $admin_php_part1 and $admin_php_part2 and $admin_php_part3
}