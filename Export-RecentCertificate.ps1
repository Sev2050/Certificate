#Created 8/10/2023
#Author: Thomas White
#Version 1.0
#Description: This function finds recently created certificates and then asking you what one you want to export. You must define before hand where you want to export certificate to and if you want localmachine or current user

function Export-RecentCertificate {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("LocalMachine", "CurrentUser")]
        [string]$CertificateStore,

        [String]$FilePath
    )

    $certificates = @(Get-ChildItem -Path Cert:\$CertificateStore\My | Where-Object { $_.NotBefore -gt (Get-Date).AddDays(-30) } | Select-Object Subject, NotBefore, Thumbprint, PSPath)

    if ($certificates.Count -eq 0) {
        Write-Host "No recent certificates found."
        return
    }

    $index = 1
    $certificates | ForEach-Object {
        Write-Host "$index. $($_.Thumbprint) - $($_.Subject) ($($_.NotBefore))"
        $index++
    }

    $selectedIndex = Read-Host "Enter the number of the certificate you want to export"

    if ($selectedIndex -lt 1 -or $selectedIndex -gt $certificates.Count) {
        Write-Host "Invalid selection!"
        return
    }

    $selectedCert = $certificates[$selectedIndex - 1]

    $password = Read-Host "Enter a password for the exported PFX" -AsSecureString

    $exportPath = "$filepath\$($selectedCert.Thumbprint).pfx"

    try {
        Export-PfxCertificate -cert $selectedCert.PSPath -FilePath $exportPath -Password $password
        Write-Host "Certificate exported to $exportPath"
    } catch {
        Write-Error "Failed to export certificate: $_"
    }
}

# Example usage:
# Export-RecentCertificate -CertificateStore CurrentUser
