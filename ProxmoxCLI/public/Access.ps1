function Request-Ticket {
    <#
    .SYNOPSIS
    Create or Verify authentication ticket.

    .DESCRIPTION
    Create or Verify authentication ticket.

    .PARAMETER Credential
    Username, Password, Realm(Domain). Password can also be a valid ticket.

    .PARAMETER OTP
    One-Time password for Two-factor atuhentication.

    .PARAMETER Path
    Verify ticket, and check if user have access 'privs' on 'path'

    .PARAMETER Privs
    Verify ticket, and check if user have access 'privs' on 'path'

    .PARAMETER Realm
    You can optionally pass the realm useing this parameter.
    Normally the realm is simply added to the username <username>@<realm>,
    but this cmdlet takes care of that for you in the Credential parameter as the domain in <domain>/user.
    This is used only if you want to override that the domain part.

    .EXAMPLE
    Request-Ticket -Credential (Get-Credential)

    .EXAMPLE
    Request-Ticket -Credential (Get-Credential) -OTP "123456" -Realm "promxox1"

    .EXAMPLE
    Request-Ticket -Credential (Get-Credential) -OTP "123456" -Realm "promxox1"

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [pscredential]
        $Credential,
        [string]
        $OTP,
        [string]
        $Path,
        [string]
        $Privs,
        [ValidateScript( { $_ -in (Get-Realm).realm })]
        [string]
        $Realm
    )
    $Options = @()
    $Options.Add('username', $Credential.UserName)
    $Options.Add('password', $Credential.GetNetworkCredential().Password)
    if ($OTP) {
        $Options.Add('otp', $OTP)
    }
    if ($Path) {
        $Options.Add('path', $Path)
    }
    if ($Privs) {
        $Options.Add('privs', $Privs)
    }
    if ($Realm) {
        $Options.Add('realm', $Realm)
    }
    elseif (-not [String]::IsNullOrEmpty($Credential.GetNetworkCredential().Domain) -and -not [String]::IsNullOrWhiteSpace($Credential.GetNetworkCredential().Domain)) {
        $Options.Add('realm', $Credential.GetNetworkCredential().Domain)
    }
    return (Invoke-ProxmoxAPI -Method Post -Resource "access/ticket" -Options $Options)
}

function Get-Realm {
    <#
    .SYNOPSIS
    Gets the authenication domains or auth configutation of specific servers

    .DESCRIPTION
    Gets the authenication domains or auth configutation of specific servers

    .PARAMETER Realm
    Returns the auth configuration of a specific server

    .EXAMPLE
    Get-Realm

    .EXAMPLE
    Get-Realm -Realm "proxmox-realm"

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [string[]]
        $Realm
    )
    if ($Realm) {
        return $Realm | ForEach-Object {
            Invoke-ProxmoxAPI -Method Post -Resource "access/domains/$Realm"
        }
    }
    else {
        return Invoke-ProxmoxAPI -Method Post -Resource "access/domains"
    }
}
New-Alias -Name 'Verify-Ticket' -Value 'Request-Ticket'
Export-ModuleMember -Cmdlet @('Get-Realm' , 'Request-Ticket') -Alias @('Verify-Ticket')