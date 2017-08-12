function Get-Node {
    Param(
        # Parameter help description
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]
        $node
    )
    # Check if ticket has expired or was even created
    if ((Get-Date).Ticks -le $Script:PveTickets.Expire -or $null -ne $Script:PveTickets) {
        # Setup Headers and cookie
        $ContentType = "application/json"
        $Header = @{
            CSRFPreventionToken = $Script:PveTickets.CSRFPreventionToken
        }
        $cookie = New-Object System.Net.Cookie
        $cookie.Name = "PVEAuthCookie"
        $cookie.Path = "/"
        $cookie.Domain = $Script:PveTickets.Server
        $cookie.Value = $Script:PveTickets.Ticket
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $session.cookies.add($cookie)

        if ($Script:PveTickets.BypassSSLCheck) {
            $CertificatePolicy = GetCertificatePolicy
            SetCertificatePolicy -Func (GetTrustAllCertsPolicy)
        }
        if ($node) {
            $node | ForEach-Object {
                #asdf
                $Url = "https://$($Script:PveTickets.Server):8006/api2/json/nodes/$_"
                try {
                    $response = Invoke-RestMethod -Method Get -Uri $Url -WebSession $session -Headers $Header -Verbose -ContentType $ContentType
                    # Do some recursion on this data? 
                }
                catch {
                    Write-Error $_
                }
            }
        }
        else {
            $Url = "https://$($Script:PveTickets.Server):8006/api2/json/nodes"
            try {
                $response = Invoke-RestMethod -Method Get -Uri $Url -WebSession $session -Headers $Header -Verbose -ContentType $ContentType    
            }
            catch {
                Write-Error $_
            }
        }

        if ($Script:PveTickets.BypassSSLCheck) {
            SetCertificatePolicy -Func ($CertificatePolicy)
        }
        return $response.data
    }
    else {
        Write-Error "Not connected to server, run Connect-PveServer first."
        return $false
    }
}


Export-ModuleMember -Function @('Get-Node')