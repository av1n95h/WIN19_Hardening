

function auditsettings {
    
    auditpol.exe /set /subcategory:"IPsec Driver" /success:enable /failure:enable
    auditpol.exe /set /subcategory:"Security State Change" /success:enable /failure:enable
    auditpol.exe /set /subcategory:"Security System Extension" /success:enable /failure:enable
    auditpol.exe /set /subcategory:"System Integrity" /success:enable /failure:enable
    auditpol.exe /set /category:"Account Management" /Subcategory:"User Account Management" /success:enable /failure:enable
    auditpol.exe /set /category:"Object Access" /Subcategory:"Other Object Access Events"  /success:enable /failure:enable
    auditpol.exe /set /category:"Account Logon" /Subcategory:"Credential Validation" /failure:enable
    auditpol.exe /set /category:"System" /Subcategory:"Security System Extension" /success:enable 
    auditpol.exe /set /category:"System" /Subcategory:"IPsec Driver" /success:enable /failure:enable
    auditpol.exe /set /category:"Account Management" /Subcategory:"Other Account Management Events" /success:enable
    auditpol.exe /set /category:"Logon/Logoff" /subcategory:"Account Lockout" /failure:enable 
    auditpol.exe /set /category:"Detailed Tracking" /subcategory:"Process Creation" /success:enable
    auditpol.exe /set /category:"Policy change" /Subcategory:"Authorization Policy Change" /success:enable /failure:enable
    auditpol.exe /set /category:"Privilege Use" /Subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
}
auditsettings | Out-Null


#Windows Account Policy Settings
function accounts {
    net accounts /lockoutwindow:15
    net accounts /MiNPWLEN:14
    net accounts /uniquepw:24
    net accounts /minpwage:1
    net accounts /lockoutthreshold:3
    net accounts /lockoutduration:15
    Rename-LocalUser -Name Guest -NewName Forbidden
}
accounts | Out-Null

Write-Host "Renaming Guest user to Forbidden" 


function RequireSecuritySignature_Workstation {

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name RequireSecuritySignature -Value 1
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name RequireSecuritySignature 
}

function RequireSecuritySignature_LanManServer {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name RequireSecuritySignature -Value 1
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name RequireSecuritySignature 
}

function SMB1 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Value 0
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1
}

function EnableSecuritySignature {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name EnableSecuritySignature -Value 1
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name EnableSecuritySignature
}

function NoLMHash {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name NoLMHash -Value 1 
    Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name NoLMHash
}

function mrxsmb10 {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Value Start
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name Start -Value 4
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name Start
    
}

function RestrictRemoteSAM {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name RestrictRemoteSAM -Value "O:BAG:BAD:(A;;RC;;;BA)"
    Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name RestrictRemoteSAM 
}

function ConsentPromptBehaviorAdmin {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorAdmin -Value 2
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorAdmin
    
}

function allownullsessionfallback {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"  -Value allownullsessionfallback  -Force |Out-Null 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name allownullsessionfallback -Value 0
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name allownullsessionfallback
}

function NTLMMinClientSec {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinClientSec -Value 537395200  
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinClientSec
}

function NTLMMinServerSec {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinServerSec -Value 537395200 -Force 
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinServerSec
}
    
function RestrictAnonymous {
    #New-Item -Path  "HKLM:\System\CurrentControlSet\Control\Lsa"  -Value RestrictAnonymous -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymous -Value 1
    Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymous
}


function LmCompatibilityLevel {
    #New-Item -Path "HKLM:\System\CurrentControlSet\Control\Lsa"  -Value LmCompatibilityLevel -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name LmCompatibilityLevel -Value 5
    Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name LmCompatibilityLevel

}

function AllowIndexingEncryptedStoresOrItems {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\"  -Value AllowIndexingEncryptedStoresOrItems -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" -Name AllowIndexingEncryptedStoresOrItems -Value 0
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" -Name AllowIndexingEncryptedStoresOrItems
}

function InactivityTimeoutSec {
    #New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"  -Value InactivityTimeoutSecs -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name InactivityTimeoutSecs -Value 900
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name InactivityTimeoutSecs
    
}

function ProcessCreationIncludeCmdLine_Enabled {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\"  -Value ProcessCreationIncludeCmdLine_Enabled -Force |Out-Null 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" -Name ProcessCreationIncludeCmdLine_Enabled -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" -Name ProcessCreationIncludeCmdLine_Enabled
}

function EnableScriptBlockLogging {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"  -Value EnableScriptBlockLogging -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name EnableScriptBlockLogging -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name EnableScriptBlockLogging
}

function SCENoApplyLegacyAuditPolicy {
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"  -Value SCENoApplyLegacyAuditPolicy -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -Value 1
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy
}

function NoLockScreenSlideshowName {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"  -Value NoLockScreenSlideshow         -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\" -Name NoLockScreenSlideshow -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\" -Name NoLockScreenSlideshow
}
       
function UseLogonCredential {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\"  -Value UseLogonCredential       -Force |Out-Null 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" -Name UseLogonCredential -Value 0
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" -Name UseLogonCredential
}

function DisableWebPnPDownload {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"  -Value DisableWebPnPDownload -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" -Name DisableWebPnPDownload -Value 1 
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" -Name DisableWebPnPDownload
    
}

function DisableHTTPPrinting {
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"  -Value DisableHTTPPrinting -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" -Name DisableHTTPPrinting -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" -Name DisableHTTPPrinting

}

function DontDisplayNetworkSelectionUI {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"  -Value DontDisplayNetworkSelectionUI  -Force |Out-Null     
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name DontDisplayNetworkSelectionUI -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name DontDisplayNetworkSelectionUI
}

function EnableSmartScreen {
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"  -Value EnableSmartScreen -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnableSmartScreen -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnableSmartScreen
}

function SupportedEncryptionTypes {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"  -Value SupportedEncryptionTypes -Force |Out-Null 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name SupportedEncryptionTypes -Value 2147483640
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name SupportedEncryptionTypes  
}
 
function DisableInventory {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\"  -Value DisableInventory         -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\" -Name DisableInventory -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\" -Name DisableInventory    
}

function Client_AllowUnencryptedTraffic {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"  -Value AllowUnencryptedTraffic   -Force |Out-Null  
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowUnencryptedTraffic  -Value 0     
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowUnencryptedTraffic
}

function Client_AllowDigest {

    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"  -Value AllowDigest         -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowDigest  -Value 0
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowDigest 
}
      
function Client_AllowBasic {
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"  -Value AllowBasic          -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowBasic -Value 0
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowBasic
}

function Service_AllowBasic {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"  -Value AllowBasic        -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowBasic -Value 0
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowBasic
}

function AllowUnencryptedTraffic {
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"  -Value AllowUnencryptedTraffic   -Force |Out-Null   
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowUnencryptedTraffic -Value 0  
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowUnencryptedTraffic
    
}

function DisableRunAs {
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"  -Value DisableRunAs  -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name DisableRunAs -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name DisableRunAs
    
}

function EnumerateAdministrators {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\"  -Value EnumerateAdministrators   -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" -Name EnumerateAdministrators -Value 0
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" -Name EnumerateAdministrators
}



function Application_MaxSize {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\"  -Value MaxSize         -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" -Name MaxSize -Value 32768  
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" -Name MaxSize
}

function Security_MaxSize {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\"  -Value MaxSize        -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" -Name MaxSize -Value 196608
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" -Name MaxSize
}

function System_MaxSize {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\"  -Value MaxSize         -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" -Name MaxSize -Value 32768 
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" -Name MaxSize
}

function EnableUserControl {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"  -Value EnableUserControl        -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name EnableUserControl -Value 0    
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name EnableUserControl
}

function AlwaysInstallElevated {
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"  -Value AlwaysInstallElevated -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name AlwaysInstallElevated -Value 0
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name AlwaysInstallElevated
}

function NoAutoplayfornonVolume {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"  -Value NoAutoplayfornonVolume -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoAutoplayfornonVolume -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoAutoplayfornonVolume
}

function AllowOnlineID {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\"  -Value AllowOnlineID -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" -Name AllowOnlineID -Value 0 
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" -Name AllowOnlineID    
}

function DCSettingIndex {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"  -Value DCSettingIndex -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name DCSettingIndex -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name DCSettingIndex
    
}

     
function ACSettingIndex {
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"  -Value ACSettingIndex   -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name ACSettingIndex -Value 1 
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name ACSettingIndex
    
}

function NoGPOListChanges {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"  -Value NoGPOListChanges -Force |Out-Null   
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" -Name NoGPOListChanges -Value 0
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" -Name NoGPOListChanges
}

function AllowProtectedCreds {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\"  -Value AllowProtectedCreds -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" -Name AllowProtectedCreds -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" -Name AllowProtectedCreds
}

function AllowInsecureGuestAuth {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"  -Value AllowInsecureGuestAuth -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -Name AllowInsecureGuestAuth -Value 0
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -Name AllowInsecureGuestAuth
}

function TcpIp_DisableIPSourceRouting {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"  -Value DisableIPSourceRouting -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name DisableIPSourceRouting -Value 2
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name DisableIPSourceRouting
}

function Tcpip_EnableICMPRedirect {
    #New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"  -Value EnableICMPRedirect  -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name EnableICMPRedirect -Value 0 
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name EnableICMPRedirect
}

function Tcpip6_DisableIPSourceRouting {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"  -Value DisableIPSourceRouting  -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -Name DisableIPSourceRouting -Value 2   
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -Name DisableIPSourceRouting   
}

function NoNameReleaseOnDemand {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\"  -Value NoNameReleaseOnDemand   -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" -Name NoNameReleaseOnDemand -Value 1 
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" -Name NoNameReleaseOnDemand
}

function NoAutorun {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"  -Value NoAutorun  -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoAutorun -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoAutorun
}

function NoDriveTypeAutoRun {
    #New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"  -Value NoDriveTypeAutoRun  -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoDriveTypeAutoRun -Value 0xff 
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoDriveTypeAutoRun
}
    
function fPromptForPassword {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"  -Value fPromptForPassword    -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fPromptForPassword -Value 1    
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fPromptForPassword
}

function DisablePasswordSaving {
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"  -Value DisablePasswordSaving -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name DisablePasswordSaving -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name DisablePasswordSaving
}

function MinEncryptionLevel {
    #New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Value MinEncryptionLevel -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MinEncryptionLevel -Value 3
    Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MinEncryptionLevel
    
}

function fDisableCdm {
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"  -Value fDisableCdm        -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableCdm -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableCdm
}

function fEncryptRPCTraffic {
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"  -Value fEncryptRPCTraffic  -Force |Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fEncryptRPCTraffic -Value 1
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fEncryptRPCTraffic

}

function RestrictRemoteClients {
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" -Value RestrictRemoteClients -Force |Out-Null |Out-Null 
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" -Name RestrictRemoteClients -Value 1
    Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" -Name RestrictRemoteClients
   
}

function scremoveoption {
    set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name scremoveoption -Value 2
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name scremoveoption
    
}

function UseMachineId {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name UseMachineId -Value 1
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name UseMachineId
}


function after_Hardening {
    auditpol.exe /get /subcategory:"Security State Change" 
    auditpol.exe /get /subcategory:"System Integrity"
    auditpol.exe /get /category:"Account Management" /Subcategory:"User Account Management" 
    auditpol.exe /get /category:"Object Access" /Subcategory:"Other Object Access Events"  
    auditpol.exe /get /category:"Account Logon" /Subcategory:"Credential Validation" 
    auditpol.exe /get /category:"System" /Subcategory:"Security System Extension"
    auditpol.exe /get /category:"System" /Subcategory:"IPsec Driver"
    auditpol.exe /get /category:"Account Management" /Subcategory:"Other Account Management Events" 
    auditpol.exe /get /category:"Logon/Logoff" /subcategory:"Account Lockout"
    auditpol.exe /get /category:"Detailed Tracking" /subcategory:"Process Creation" 
    auditpol.exe /get /category:"Policy change" /Subcategory:"Authorization Policy Change" 
    auditpol.exe /get /category:"Privilege Use" /Subcategory:"Sensitive Privilege Use"

    net accounts
    
    RequireSecuritySignature_Workstation
    RequireSecuritySignature_LanManServer
    SMB1
    EnableSecuritySignature
    NoLMHash
    mrxsmb10
    RestrictRemoteSAM 
    ConsentPromptBehaviorAdmin
    allownullsessionfallback
    NTLMMinClientSec
    NTLMMinServerSec
    RestrictAnonymous
    LmCompatibilityLevel
    AllowIndexingEncryptedStoresOrItems
    InactivityTimeoutSec
    ProcessCreationIncludeCmdLine_Enabled
    EnableScriptBlockLogging
    SCENoApplyLegacyAuditPolicy
    NoLockScreenSlideshowName
    UseLogonCredential
    DisableWebPnPDownload
    DisableHTTPPrinting
    DontDisplayNetworkSelectionUI
    EnableSmartScreen
    SupportedEncryptionTypes
    DisableInventory
    Client_AllowUnencryptedTraffic
    Client_AllowDigest
    Client_AllowBasic
    Service_AllowBasic
    DisableRunAs
    EnumerateAdministrators
    Application_MaxSize
    Security_MaxSize
    System_MaxSize
    EnableUserControl
    AlwaysInstallElevated
    NoAutoplayfornonVolume
    AllowOnlineID
    DCSettingIndex
    ACSettingIndex
    NoGPOListChanges
    AllowProtectedCreds
    AllowInsecureGuestAuth
    #TcpIp_DisableIPSourceRouting
    #Tcpip_EnableICMPRedirect
    #Tcpip6_DisableIPSourceRouting
    NoNameReleaseOnDemand
    NoAutorun
    NoDriveTypeAutoRun
    fPromptForPassword
    DisablePasswordSaving
    MinEncryptionLevel
    fDisableCdm
    fEncryptRPCTraffic
    RestrictRemoteClients
    scremoveoption
    UseMachineId

    Write-Host "Renaming Guest user to Forbidden" 
}

Write-Host "Following settings are changed after hardening. The changes are saved to C:\Users\Administrator\Documents\After_Hardening.txt" -ForegroundColor Green

after_Hardening | Out-File -FilePath "C:\Users\Administrator\Documents\After_Hardening.txt"


