rule LuaJIT_Malware
{
    meta:
        author = "Nimish"
        description = "Detects LuaJIT malware"
        date = "2024-08-05"
        version = "1.0"

    strings:
        $mz = { 4d 5a }
        $s1 = "luaJIT_BC_config"
        $s2 = "luaJIT_BC_hider"
        $s3 = "luaJIT_BC_install"
        $s4 = "luaJIT_BC_ltn12"
        $s5 = "luaJIT_BC_main"
        $s6 = "luaJIT_BC_md5"
        $s7 = "luaJIT_BC_mime"
        $s8 = "luaJIT_BC_miner"
        $s9 = "luaJIT_BC_process"
        $s10 = "luaJIT_BC_socket"
        $s11 = "luaJIT_BC_socket_headers"
        $s12 = "luaJIT_BC_socket_http"
        $s13 = "luaJIT_BC_socket_url"
        $s14 = "luaJIT_BC_sysinfo"
        $s15 = "luaJIT_BC_updater.release.exe"

    condition:
        ($mz at 0) and any of ($s*)
}
