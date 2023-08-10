function Deploy-Certificate {
    param (
        [Parameter(Mandatory=$true)]
        [string]$CertFilePath,

        [Parameter(Mandatory=$true)]
        [string]$CertExportPath,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("Computer")]
        [string[]]$ComputerParameter,

        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$Credentials,

        [string]$IisBinding
    )

    $computers = if ($ComputerParameter -like "*.csv") {
        Import-Csv $ComputerParameter | ForEach-Object { $_.ComputerName }
    } else {
        $ComputerParameter
    }

    $scriptToRun = {
        param ($CertExportPath, $Credentials, $IisBinding)

        # Import the certificate into the certificate store
        Import-PfxCertificate -FilePath $CertExportPath -CertStoreLocation Cert:\LocalMachine\My -Password $Credentials

        # Check for IIS binding and if IIS is installed
        if ($IisBinding -and (Get-WindowsFeature -Name Web-Server)) {
            Import-Module WebAdministration
            
            # Assuming IIS binding requires the site name and the certificate is identified by its thumbprint
            $cert = (Get-PfxData -FilePath $CertExportPath -Password $Credentials).EndEntityCertificates.Thumbprint

            # Bind the certificate to the specified IIS site
            if ($cert) {
                $binding = Get-WebBinding -Name $IisBinding -Protocol "https"
                $binding.AddSslCertificate($cert, "my")
            } else {
                Write-Error "Certificate not found in store."
            }
        }
    }

    foreach ($computer in $computers) {
        $CopyCertLocation = $CertExportPath.Replace(":", "$")

        # Copy the certificate to the remote machine
        Copy-Item -Path $CertFilePath -Destination "\\$computer\$CopyCertLocation" -Force

        # Invoke the script block on the remote machine
        Invoke-Command -ComputerName $computer -ScriptBlock $scriptToRun -ArgumentList $CertExportPath, $Credentials, $IisBinding
    }
}

# Example:
# Deploy-Certificate -CertFilePath "C:\localpath\cert.pfx" -CertExportPath "C$\remotepath\cert.pfx" -ComputerParameter "computers.csv" -Credentials (ConvertTo-SecureString "Password123" -AsPlainText -Force) -IisBinding @{SiteName="Default Web Site"; HostHeader=""; Thumbprint="xxxxxx"}
