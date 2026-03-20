rule Elite_Cheat_Detection {
    meta:
        description = "Расширенный детект читов и инжекторов для Minecraft"
        author = "mqclass"
    strings:
        $v1 = "vape_v4" nocase
        $v2 = "vape.rip" nocase
        $a1 = "Akrien" nocase
        $c1 = "Celestial" nocase
        $m1 = "Meteor Client" nocase
        $imp1 = "GetProcAddress"
        $imp2 = "VirtualAlloc"
        $imp3 = "NtCreateThreadEx"
        $imp4 = "LdrLoadDll"
        $inj1 = "manual_map" nocase
        $inj2 = "reflective_loader" nocase
        $java1 = "Lnet/minecraft/client/"
        $java2 = "Lorg/lwjgl/"
        $java3 = "net/minecraft/v1_16_R3"
    condition:
        uint16(0) == 0x5A4D and (
            (2 of ($v*, $a*, $c*, $m*)) or
            (3 of ($imp*)) or
            (1 of ($inj*)) or
            (2 of ($java*))
        )
}

rule Suspicious_Packer {
    meta:
        description = "Детект упаковщиков и крипторов"
    strings:
        $upx     = "UPX!"
        $vmp     = ".vmp"
        $themida = "Themida" nocase
    condition:
        any of them
}
