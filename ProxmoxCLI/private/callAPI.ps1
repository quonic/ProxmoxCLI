function callGet ($Resource) {
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
        $Url = "https://$($Script:PveTickets.Server):8006/api2/json/$Resource"
        try {
            $response = Invoke-RestMethod -Method Get -Uri $Url -WebSession $session -Headers $Header -Verbose -ContentType $ContentType    
        }
        catch {return $false}

        return $response.data
    }
}