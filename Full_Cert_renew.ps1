<#
.SYNOPSIS
   This renews the certificate and also exports the certificate then to be placed onto other servers that have been imported from the CSV

.DESCRIPTION
   This renews the certificate and also exports the certificate then to be placed onto other servers that have been imported from the CSV

.PARAMETER Format
  test

.EXAMPLE
    None at this time

.NOTES
   File Name      : Renew-Certificate.ps1
   Author         : Thomas White
   Date           : 06/08/2023
   Version        : 1.0

.LINK
   
#>

#Import Servers and Cert info
$ServerssandCerts = Import-Csv -LiteralPath c:\temp\certservers.csv


#Choose first server and check for https cert bound and get thumbprint
Foreach ($ServerandCert in $ServerssandCerts)
    {
        If ($ServerandCert.Primary -eq "True")
            {
                # Bind the certificate to the IIS site
                 Write-Host "Checking for cert bound to IIS: $ServerandCert.server"
                 $scriptBlock = 
                 {
                param($thumbprint)
                    Import-Module WebAdministration
                    Remove-Item -Path "C:\temp\CertReq.ps1"
                    $OldCert = Get-ChildItem -Path IIS:\SslBindings | Select-Object PSComputerName,Thumbprint,port
                    $OldCertTP = $OldCert.Thumbprint
                    New-Item "C:\temp\CertReq.ps1" -ItemType File -Value "certreq -Enroll -machine -q -cert '$OldCertTP' Renew ReuseKeys"
                 }
               Invoke-Command -ComputerName $ServerandCert.servers -ScriptBlock $scriptBlock
               Write-Host "Certificate to renew $OldCertTP"


                #Create scheduled task and have it run the ps1 right away 
                $scriptBlock = 
                 {
                    #This here for only testing
                    Unregister-ScheduledTask -TaskName "RenewCert" -Confirm:$false

                    #Creating Certificate
                    $currenttime = Get-Date
                    $triggertime = $currenttime.AddSeconds(15)
                    $A = New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory "C:\Temp\" -Argument '-NonInteractive -NoLogo -NoProfile -Command ".\CertReq.ps1"'
                    $T = New-ScheduledTaskTrigger -Once -At $triggertime
                    $P = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                    $S = New-ScheduledTaskSettingsSet
                    $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S 
                    Register-ScheduledTask RenewCert -InputObject $D

                 }
                    Invoke-Command -ComputerName $ServerandCert.servers -ScriptBlock $scriptBlock
                    Start-Sleep -Seconds 40
               
                #
                # Get selected certificate
                $scriptBlock = 
                 {
                    $certificates = Get-ChildItem -Path Cert:\LocalMachine\My

                    # List all certificates
                    Write-Host "List of available certificates:"
                    $index = 1
                    foreach($certificate in $certificates){
                        Write-Host "$index : $($certificate.Subject)"
                        $index++
                    }

                    # Ask user to choose a certificate
                    $selected = Read-Host -Prompt "Enter the number of the certificate you want to export"

                    # Check if selected certificate is valid
                    if($selected -lt 1 -or $selected -gt $certificates.Count){
                        Write-Host "Invalid selection"
                        return
                    }
                    $selectedCertificate = $certificates[$selected - 1]

                    # Ask user to provide a password for the exported pfx
                    $password = Read-Host -Prompt "Enter the password for the exported .pfx file" -AsSecureString

                    # Export the selected certificate with private key
                    $exportPath = "C:\temp\$($selectedCertificate.Thumbprint).pfx"
                    Export-PfxCertificate -cert $selectedCertificate.PSPath -FilePath $exportPath -Password $password

                    Write-Host "Certificate exported at $exportPath"
                }
                    $ExportCert = Invoke-Command -ComputerName $ServerandCert.servers -ScriptBlock $scriptBlock
                    #Path to certificate that is exported
                    $FilePath = Join-Path -Path '\\' -ChildPath $ServerandCert.servers | Join-Path -ChildPath '\c$\temp\'
                    $ExportCertLocation = Join-Path -Path $FilePath -ChildPath $ExportCert.Name
            }
            else {
                #Secondary Servers
            }
            

    }


#After cert is renewed copy certificate and export it and request password
# Get all certificates






#Then place certificate on other servers and import and bind certs
#New Certificate Location

#Location on everyone server to be created if it doesn't exist
$LocalNewPath = "C$\Temp"
$LocalPath = "C:\Temp"
$LocalCert = "C:\Temp\$(Split-Path $ExportCertLocation -Leaf)"


################################################################################################################################

# *** Entry Point to Script ***


#Get Cert Password
#$CertPass = Get-Credential -UserName 'Type PFX password below' -Message 'Enter password below'
$CertPass = Read-Host -Prompt "Type PFX password" -AsSecureString


#Copy pfx Cert to other servers
Foreach ($ServerandCert in $ServerssandCerts)
{
$Server = $ServerandCert.servers
Write-Host Copying file $ExportCertLocation to $Server $LocalNewPath -ForegroundColor Yellow
#New-Item -Path \\$Server\$LocalNewPath -ItemType Directory -ErrorAction Ignore 
Copy-Item -Path $ExportCertLocation -Destination \\$Server\$LocalNewPath
}

Start-Sleep -Seconds 5


Foreach ($ServerandCert in $ServerssandCerts){

    # Import certificate on the remote server
    Write-Host "Importing certificate on server: $ServerandCert.servers"
    $scriptBlock = {
        param($LocalCert, $CertPass)
        Import-PfxCertificate -FilePath $LocalCert -CertStoreLocation Cert:\LocalMachine\My -Password $CertPass -Exportable
    }
    Invoke-Command -ComputerName $ServerandCert.servers -ScriptBlock $scriptBlock -ArgumentList "$LocalPath\$(Split-Path $LocalCert -Leaf)", $CertPass

    # Bind the certificate to the IIS site
    Write-Host "Binding certificate to IIS on server: $ServerandCert.servers"
    $scriptBlock = {
        param($thumbprint)
        Import-Module WebAdministration
        $binding = Get-WebBinding -name "Hyrule" -Protocol https
        $binding.AddSslCertificate($thumbprint, "my")

        
    }
    #Get Certificate
    $thumbprint = (Get-PfxData -FilePath $LocalCert -Password $CertPass).EndEntityCertificates.Thumbprint
    Invoke-Command -ComputerName $ServerandCert.servers  -ScriptBlock $scriptBlock -ArgumentList $thumbprint
}
pause
