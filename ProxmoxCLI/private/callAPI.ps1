function callGet {
    #[CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]
        $Resource,
        [hashtable] $Options
    )
    if ((Get-Date).Ticks -le $Script:PveTickets.Expire -or $null -ne $Script:PveTickets) {
        
        # Bypass ssl checking or servers without a public cert or internal CA cert
        if ($Script:PveTickets.BypassSSLCheck) {
            $CertificatePolicy = GetCertificatePolicy
            SetCertificatePolicy -Func (GetTrustAllCertsPolicy)
        }

        # Setup Headers and cookie for splatting
        $splat = PrepareGetRequest
        $Query = ""
        If ($Options) {
            $Options.keys | ForEach-Object {
                $Query = $Query + "$_=$($Options[$_])&"
            }
            $Query = $Query.TrimEnd("&")
        }
        try {
            $response = Invoke-RestMethod -Uri "https://$($Script:PveTickets.Server):8006/api2/json/$($Resource)?$($Query)" @splat
        }
        catch {return $false}
        
        # restore original cert policy
        SetCertificatePolicy -Func $CertificatePolicy
        
        return $response.data
    }
    else {
        # TODO Impliment updating ticket
        return $false
    }
}

function PreparePostRequest() {
    $cookie = New-Object System.Net.Cookie -Property @{
        Name   = "PVEAuthCookie"
        Path   = "/"
        Domain = $Script:PveTickets.Server
        Value  = $Script:PveTickets.Ticket
    }
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.cookies.add($cookie)
    $request = New-Object -TypeName PSCustomObject -Property @{
        Method      = "Post"
        Headers     = @{CSRFPreventionToken = $Script:PveTickets.CSRFPreventionToken}
        WebSession  = $session
        ContentType = "application/json"
    }
    return $request
}

function PrepareGetRequest() {
    $cookie = New-Object System.Net.Cookie -Property @{
        Name   = "PVEAuthCookie"
        Path   = "/"
        Domain = $Script:PveTickets.Server
        Value  = $Script:PveTickets.Ticket
    }
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.cookies.add($cookie)
    $request = @{
        Method      = "Get"
        WebSession  = $session
        ContentType = "application/json"
    }
    return $request
}

function PrepareDeleteRequest() {
    $cookie = New-Object System.Net.Cookie -Property @{
        Name   = "PVEAuthCookie"
        Path   = "/"
        Domain = $Script:PveTickets.Server
        Value  = $Script:PveTickets.Ticket
    }
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.cookies.add($cookie)
    $request = New-Object -TypeName PSCustomObject -Property @{
        Method      = "Delete"
        Headers     = @{CSRFPreventionToken = $Script:PveTickets.CSRFPreventionToken}
        WebSession  = $session
        ContentType = "application/json"
    }
    return $request
}