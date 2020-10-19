function Invoke-ProxmoxAPI {
    #[CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]
        $Resource,
        [string]
        $Method,
        [hashtable]
        $Options
    )
    if ($null -eq $Script:PveTickets) {
        # Check if we even have a ticket
        Write-Error "Please connect usinge Connect-PveServer."
        return $false
    }
    # if ((Get-Date).Ticks -le $Script:PveTickets.Expire) {
    #     # Check if ticket expired and grab a new one
    #     Connect-PveServer -Server $Script:PveTickets.Server
    # }
    # Bypass ssl checking or servers without a public cert or internal CA cert
    if ($Script:PveTickets.BypassSSLCheck) {
        $CertificatePolicy = GetCertificatePolicy
        SetCertificatePolicy -Func (GetTrustAllCertsPolicy)
    }

    # Setup Headers and cookie for splatting
    switch ($Method) {
        Get { $splat = PrepareGetRequest; break }
        Post { $splat = PreparePostRequest; break }
        Put { $splat = PreparePutRequest; break }
        Delete { $splat = PrepareGetRequest; break }
        Default { $splat = PrepareGetRequest }
    }

    $Query = ""
    if ($Options) {
        $Query = "?"
        $Options.keys | ForEach-Object {
            if ($Options[$_]) {
                $Query = $Query + "$_=$($Options[$_])&"
            }
        }
        $Query = $Query.TrimEnd("&")
    }
    try {
        Write-Debug "REST call: https://$($Script:PveTickets.Server):8006/api2/json/$($Resource)$($Query)"
        $response = Invoke-RestMethod -Uri "https://$($Script:PveTickets.Server):8006/api2/json/$($Resource)$($Query)" @splat
        Write-Debug "REST response: $($response.data)"
    }
    catch { return $false }


    if ($Script:PveTickets.BypassSSLCheck) {
        # restore original cert policy
        SetCertificatePolicy -Func $CertificatePolicy
    }

    return $response.data
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
        Headers     = @{CSRFPreventionToken = $Script:PveTickets.CSRFPreventionToken }
        WebSession  = $session
        ContentType = "application/json"
    }
    return $request
}

function PreparePutRequest() {
    $cookie = New-Object System.Net.Cookie -Property @{
        Name   = "PVEAuthCookie"
        Path   = "/"
        Domain = $Script:PveTickets.Server
        Value  = $Script:PveTickets.Ticket
    }
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.cookies.add($cookie)
    $request = New-Object -TypeName PSCustomObject -Property @{
        Method      = "Put"
        Headers     = @{CSRFPreventionToken = $Script:PveTickets.CSRFPreventionToken }
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
        Headers     = @{CSRFPreventionToken = $Script:PveTickets.CSRFPreventionToken }
        WebSession  = $session
        ContentType = "application/json"
    }
    return $request
}