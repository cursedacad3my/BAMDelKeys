rule Minecraft_Cheat_Elite_Logic {
    meta:
        description = "Advanced detection for MC Cheats & Injectors"
        author = "mqclass_ss_pro"
    strings:
        $pkg_vape      = "com/vape/client"
        $pkg_akrien    = "net/akrien/client"
        $pkg_expensive = "expensive/client"
        $pkg_celestial = "celestial/main"
        $m1 = "Velocity" nocase
        $m2 = "Scaffold" nocase
        $m3 = "KillAura" nocase
        $m4 = "AutoClicker" nocase
        $m5 = "Reach" nocase
        $t1 = "Ljava/lang/instrument/Instrumentation;"
        $t2 = "sun/misc/Unsafe"
        $t3 = "LdrLoadDll"
        $t4 = "NtCreateThreadEx"
        $d1 = "vape.rip" nocase
        $d2 = "akrien.net" nocase
        $d3 = "celestial.su" nocase
    condition:
        uint16(0) == 0x5A4D and (
            (1 of ($pkg_*)) or
            (1 of ($d*)) or
            (2 of ($m*) and 1 of ($t*)) or
            (3 of ($m*))
        )
}

rule Suspicious_Binary_Structure {
    meta:
        description = "Detects packing and suspicious sections"
    strings:
        $upx     = "UPX!"
        $vmp     = ".vmp"
        $themida = "Themida" nocase
    condition:
        any of them
}
