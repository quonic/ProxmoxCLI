
function Get-PveVersion () {
    # Check if ticket has expired or was even created
    if ((Get-Date).Ticks -le $Global:PveTickets.Expire -or $null -ne $Global:PveTickets) {
        # Setup Headers and cookie
        $ContentType = "application/json"
        $Url = "https://$($Global:PveTickets.Server):8006/api2/json/version"
        $Header = @{
            CSRFPreventionToken = $Global:PveTickets.CSRFPreventionToken
        }
        $cookie = New-Object System.Net.Cookie
        $cookie.Name = "PVEAuthCookie"
        $cookie.Path = "/"
        $cookie.Domain = $Global:PveTickets.Server
        $cookie.Value = $Global:PveTickets.Ticket
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $session.cookies.add($cookie)

        if ($Global:PveTickets.BypassSSLCheck) {
            $CertificatePolicy = Get-CertificatePolicy
            Set-CertificatePolicy -Func (Get-TrustAllCertsPolicy)
        }
        
        try {
            $response = Invoke-RestMethod -Method Get -Uri $Url -WebSession $session -Headers $Header -Verbose -ContentType $ContentType    
        }
        catch {
            Write-Error $_
            return $false
        }
        if ($Global:PveTickets.BypassSSLCheck) {
            Set-CertificatePolicy -Func ($CertificatePolicy)
        }
        return $response
    }
    else {
        Write-Error "Not connected to server, run Connect-PveServer first."
        return $false
    }
}


