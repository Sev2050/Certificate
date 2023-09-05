#This function does not renew the certificate but puts it into file so that Task Schedule can renew the certificate
#Created 8/10/2023
#Author: Thomas White
#Version 1.0

function Renew-IISCertificate {
    param (
        [string]$ComputerName,
        [string]$IISsite
    )

    $scriptBlock = {
        param ($thumbprint)
        
        Import-Module WebAdministration
        Remove-Item -Path "C:\temp\CertReq.ps1" -ErrorAction SilentlyContinue

        $OldCert = Get-ChildItem -Path IIS:\SslBindings | Where-Object { $_.Sites.Value -eq $using:IISsite }
        $OldCertTP = $OldCert.Thumbprint

        New-Item "C:\temp\CertReq.ps1" -ItemType File -Value "certreq -Enroll -machine -q -cert '$OldCertTP' Renew ReuseKeys"
        Write-Host "Certificate to renew $OldCertTP"
    }

    Write-Host "Checking for cert bound to IIS: $IISsite on $ComputerName"
    $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $thumbprint
    
}

# Example usage
#Renew-IISCertificate -ComputerName "ServerName" -IISsite "SiteName" -Thumbprint "ThumbprintValue"
