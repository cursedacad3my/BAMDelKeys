rule Minecraft_Cheat_Elite {
    meta:
        description = "Advanced detection for MC Cheats (Vape, Celestial, Akrien, etc.)"
        author = "mqclass_ss_pro"
        version = "2.0"
    strings:
        $f1 = "Killaura" nocase
        $f2 = "Velocity" nocase
        $f3 = "Reach" nocase
        $f4 = "AutoClicker" nocase
        $f5 = "Fly" nocase
        $f6 = "ESP" nocase
        $f7 = "ClickGUI" nocase
        $f8 = "Module" nocase
        $d1 = "vape.rip" nocase
        $d2 = "akrien.net" nocase
        $d3 = "celestial.su" nocase
        $d4 = "expensive.host" nocase
        $hex_inj1 = { 4D 5A 45 52 4F }
        $hex_inj2 = { 52 65 66 6C 65 63 74 69 76 65 4C 6F 61 64 65 72 }
        $imp1 = "NtCreateThreadEx"
        $imp2 = "LdrLoadDll"
        $imp3 = "WriteProcessMemory"
        $imp4 = "VirtualAllocEx"
    condition:
        uint16(0) == 0x5A4D and (
            (3 of ($f*)) or
            (1 of ($d*)) or
            (1 of ($hex_inj*)) or
            (2 of ($imp*))
        )
}

rule Obfuscation_And_Packers {
    meta:
        description = "Detects VMProtect, Themida, UPX and custom packers"
    strings:
        $upx = "UPX!"
        $vmp = ".vmp"
        $themida = "Themida" nocase
        $vmp_section = ".vmp0"
        $vmp_section2 = ".vmp1"
    condition:
        any of them
}

rule Java_Internal_Trace {
    meta:
        description = "Detects Java-based cheat traces in EXE/DLL"
    strings:
        $j1 = "Lnet/minecraft/client/"
        $j2 = "Lorg/lwjgl/opengl/"
        $j3 = "java/lang/ClassLoader"
    condition:
        uint16(0) == 0x5A4D and (2 of them)
}
