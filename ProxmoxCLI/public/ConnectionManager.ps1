<#
.SYNOPSIS
Connect to Proxmox server

.DESCRIPTION
Connect to Proxmox server

.PARAMETER Server
Server name or IP address

.PARAMETER Credentials
Username and password, username formated as user@pam, user@pve, or user@yourdomain

.PARAMETER BypassSSLCheck
Used for bypassing Invoke-RestMethod built in SSL checker

.EXAMPLE
Connect-PveServer -Server "192.168.128.115" -Credentials (Get-Credential -Username "root@pam") -BypassSSLCheck

.NOTES
This must be used before any other cmdlets are used
#>
function Connect-PveServer {
    [CmdletBinding()]
    param (
        [Alias("Host", "PveServer")]
        [Parameter(ValueFromPipeline)]
        [String]
        $Server,
        [SecureString]
        $Credentials,
        [Switch]
        $BypassSSLCheck
    )
    
    begin {
        # Check if ticket already exists and if it is expired
        if ((Get-Date).AddSeconds(1).Ticks -ge $Global:PveTickets.Expire -or
        $Global:PveTickets -eq $null) {
            if (-not ($Credentials)) {
                $Credential = Get-Credential -Message "Proxmox Username and password, user@pam, user@pve, or user@domain"
            }

            $UserName = $Credential.UserName
            $Password = $Credential.GetNetworkCredential().Password
            $Body = @{
                username = $UserName
                password = $Password
            }
        }
        # if (-not $Global:PveTickets) {
        #     $Global:PveTickets = New-Object -TypeName PSCustomObject
        # }
        if ($BypassSSLCheck) {
            # Trust all certs as we don't use an internal CA
            # Don't use this if you do use an internal CA or are using an external CA
            $CertificatePolicy = Get-CertificatePolicy
            Set-CertificatePolicy -Func (Get-TrustAllCertsPolicy)
        }
    }
    
    process {
        # Check if ticket already exists and if it is expired
        if ((Get-Date).Ticks -ge $Global:PveTickets.Expire -or $Global:PveTickets -eq $null) {
            $Url = "https://$($Server):8006/api2/json/access/ticket"
            $response = Invoke-RestMethod -Method Post -Uri $Url -Body $Body
            if ($response) {
                # Create variable to work with as we have a ticket for future auth
                $NewServer = @{}
                $NewServer.Server = $Server
                $NewServer.UserName = $UserName
                $NewServer.Ticket = $response.data.ticket
                $NewServer.CSRFPreventionToken = $response.data.CSRFPreventionToken
                $NewServer.Expire = (Get-Date).AddHours(2).Ticks
                if ($BypassSSLCheck) {
                    $NewServer.BypassSSLCheck = $true
                }
                if ($Global:PveTickets.Server -contains $Server) {
                    $Global:PveTickets = $Global:PveTickets | ForEach-Object {
                        if ($_.Server -notlike $Server) {$_}
                    }
                }
                $Global:PveTickets += New-Object PSObject -Property $NewServer
            }
            else {
                Write-Warning "Not able to connect to server: $Server"
            }
        }
        else {
            Write-Verbose "Ticket not expired"
            Write-Warning "Connected to server $($Global:PveTickets.Server)"
        }
    }
    
    end {
        if ($BypassSSLCheck) {
            Set-CertificatePolicy -Func ($CertificatePolicy)
        }
    }
}