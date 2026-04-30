rule AsyncRAT_Generic
{
    meta:
        description     = "Detects AsyncRAT"
        date            = "2026-04-14"
        author        = "Luis Suastegui"
        reference       = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"

    strings:
        $dotnet_magic   = "BSJB"

        $s_pbkdf2       = "Rfc2898DeriveBytes"
        $s_aes          = "AesCryptoServiceProvider"
        $s_hmac         = "HMACSHA256"

        $p_clientinfo   = "ClientInfo"   wide
        $p_saveplugin   = "savePlugin"   wide
        $p_sendplugin   = "sendPlugin"   wide
        $p_plugincls    = "Plugin.Plugin" wide
        $p_hwid         = "HWID"         wide
        $p_pong         = "pong"         wide

    condition:
        uint16(0) == 0x5A4D       
        and $dotnet_magic         
        and $s_pbkdf2             
        and $s_aes                
        and $s_hmac               
        and 4 of ($p_*)           
}


rule AsyncRAT_v057B_ScriptCompatible
{
    meta:
        description     = "AsyncRAT v0.5.7B confirmed compatible with IoC extraction script"
        date            = "2026-04-14"
        author        = "Luis Suastegui"
        reference       = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"


        salt_hex        = "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941"
        pbkdf2_iters    = "50000"
        aes_mode        = "AES-256-CBC"
        mac_algo        = "HMAC-SHA256"

    strings:
        $dotnet_magic   = "BSJB"

        $salt = {
            BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43
            00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41
        }


        $s_pbkdf2       = "Rfc2898DeriveBytes"
        $s_aes          = "AesCryptoServiceProvider"
        $s_hmac         = "HMACSHA256"


        $p_clientinfo   = "ClientInfo"   wide
        $p_saveplugin   = "savePlugin"   wide
        $p_sendplugin   = "sendPlugin"   wide
        $p_plugincls    = "Plugin.Plugin" wide
        $p_hwid         = "HWID"         wide
        $p_pong         = "pong"         wide


        $s_antidbg      = "CheckRemoteDebuggerPresent"
        $s_critical     = "RtlSetProcessIsCritical"


        $s_sandboxie    = "SbieDll.dll"  wide

    condition:
        uint16(0) == 0x5A4D       
        and $dotnet_magic         
        and $salt                 
        and $s_pbkdf2             
        and $s_aes                
        and $s_hmac               
        and 4 of ($p_*)           
        and $s_antidbg            
        and $s_critical           
        and $s_sandboxie          
}
