<#
.SYNOPSIS
Get version of Proxmox server

.DESCRIPTION
Get version information of connected Proxmox Server

.EXAMPLE
Get-PveVersion

.NOTES
Run Connect-PveServer first
#>
function Get-PveVersion () {
    # Check if ticket has expired or was even created
    if ((Get-Date).Ticks -le $Script:PveTickets.Expire -or $null -ne $Script:PveTickets) {
        # Setup Headers and cookie
        $ContentType = "application/json"
        $Url = "https://$($Script:PveTickets.Server):8006/api2/json/version"
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
        
        try {
            $response = Invoke-RestMethod -Method Get -Uri $Url -WebSession $session -Headers $Header -Verbose -ContentType $ContentType    
        }
        catch {
            Write-Error $_
            return $false
        }
        if ($Script:PveTickets.BypassSSLCheck) {
            SetCertificatePolicy -Func ($CertificatePolicy)
        }
        return $response
    }
    else {
        Write-Error "Not connected to server, run Connect-PveServer first."
        return $false
    }
}


Export-ModuleMember -Function @('Get-PveVersion')