# ============================================================
# EDIT BEFORE RUNNING
# ============================================================
$FtpSiteName   = "Default FTP Site"   # IIS FTP site name
$FtpUser       = "ftp_user"           # local account for FTP access
$FtpUserPass   = "Ch@ngeMe2024!"      # password for the FTP account
$FtpRootPath   = "C:\FTP"             # root directory for FTP files
$FtpCertDns    = "ftp.local"          # DNS name for self-signed cert
$TrustedIPs    = @("10.0.0.5", "10.0.0.6")  # IPs allowed to connect to FTP
# ============================================================

Install-WindowsFeature Web-FTP-Server, Web-FTP-Service, Web-FTP-Ext
Install-WindowsFeature Web-Server, Web-Security

New-SelfSignedCertificate -DnsName $FtpCertDns -CertStoreLocation "cert:\LocalMachine\My"

Set-WebConfigurationProperty -filter "system.ftpServer/security/ssl" -name "controlChannelPolicy" -value "SslRequire" -PSPath IIS:\ -location $FtpSiteName
Set-WebConfigurationProperty -filter "system.ftpServer/security/ssl" -name "dataChannelPolicy"    -value "SslRequire" -PSPath IIS:\ -location $FtpSiteName

$SecurePass = ConvertTo-SecureString $FtpUserPass -AsPlainText -Force
New-LocalUser -Name $FtpUser -Password $SecurePass -PasswordNeverExpires $true

$UserDir = "$FtpRootPath\$FtpUser"
New-Item -ItemType Directory -Path $UserDir -Force

icacls $UserDir /inheritance:r
icacls $UserDir /grant "${FtpUser}:(OI)(CI)(RX)"
icacls $UserDir /remove:g Everyone

Add-WebConfiguration -Filter "system.ftpServer/security/authorization" -PSPath IIS:\ -Location $FtpSiteName `
    -Value @{accessType="Allow"; users=$FtpUser; permissions="Read,Write"}

Set-WebConfigurationProperty -filter "system.ftpServer/security/authentication/anonymousAuthentication" -name enabled -value false -PSPath IIS:\ -location $FtpSiteName
Set-WebConfigurationProperty -filter "system.ftpServer/security/authentication/basicAuthentication"    -name enabled -value true  -PSPath IIS:\ -location $FtpSiteName

Set-WebConfigurationProperty -Filter "system.ftpServer/firewallSupport" -Name "dataChannelPortRange" -Value "50000-50100" -PSPath IIS:\ -Location $FtpSiteName

New-NetFirewallRule -DisplayName "FTP Passive Ports"      -Direction Inbound -Protocol TCP -LocalPort 50000-50100 -Action Allow
New-NetFirewallRule -DisplayName "FTP Command Port"       -Direction Inbound -Protocol TCP -LocalPort 21          -Action Allow
New-NetFirewallRule -DisplayName "FTP Allow Trusted IPs"  -Direction Inbound -Protocol TCP -LocalPort 21,50000-50100 -RemoteAddress $TrustedIPs -Action Allow
New-NetFirewallRule -DisplayName "FTP Block All"          -Direction Inbound -Protocol TCP -LocalPort 21,50000-50100 -Action Block


Set-WebConfigurationProperty -filter "system.applicationHost/sites/siteDefaults/ftpServer/logFile" -name "directory" -value "C:\inetpub\logs\LogFiles"
Set-WebConfigurationProperty -filter "system.applicationHost/sites/siteDefaults/ftpServer/logFile" -name "logExtFileFlags" -value "Date, Time, ClientIP, UserName, Method, UriStem, BytesSent, BytesReceived, Win32Status, ProtocolStatus"


New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Value 0


New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" "Enabled" 0

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" "Enabled" 0


Set-WebConfigurationProperty -filter "system.ftpServer/userIsolation" -name "mode" -value "Isolated" -PSPath IIS:\ -location $FtpSiteName
New-Item -ItemType Directory -Path "$FtpRootPath\LocalUser\$FtpUser" -Force


Set-WebConfigurationProperty -filter "system.ftpServer/security/ipSecurity" -name allowUnlisted -value false -PSPath IIS:\ -location $FtpSiteName

foreach ($ip in $TrustedIPs) {
    Add-WebConfiguration "system.ftpServer/security/ipSecurity/add" -value @{ipAddress=$ip; allowed="true"} -PSPath IIS:\ -Location $FtpSiteName
}


auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable


Set-WebConfigurationProperty -filter "system.ftpServer/directoryBrowse" -name "showFlags" -value "None" -PSPath IIS:\ -location $FtpSiteName
Set-WebConfigurationProperty -filter "system.ftpServer/security/authentication/anonymousAuthentication" -name "enabled" -value false -PSPath IIS:\ -location $FtpSiteName
icacls $FtpRootPath /deny Users:(W)

Write-Host "[DONE] FTP site '$FtpSiteName' hardened. User: $FtpUser  Root: $FtpRootPath"


