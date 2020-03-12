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

function Add-Realm {
    <#
    .SYNOPSIS
    Add an authentication server

    .DESCRIPTION
    Update authentication server

    .PARAMETER Realm
    Authentication domain ID

    .PARAMETER Type
    Realm type

    .PARAMETER BaseDn
    LDAP base domain name

    .PARAMETER BindDn
    LDAP bind domain name

    .PARAMETER CaPath
    Path to the CA certificate store

    .PARAMETER Cert
    Path to the client certificate

    .PARAMETER CertKey
    Path to the client certificate key

    .PARAMETER Comment
    Description

    .PARAMETER Default
    Use this as default realm

    .PARAMETER Delete
    A list of settings you want to delete

    .PARAMETER Digest
    Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.

    .PARAMETER Domain
    AD domain name

    .PARAMETER Port
    Server Port

    .PARAMETER Secure
    Use secure LDAPS protocol

    .PARAMETER Server1
    Server IP Address (or DNS name)

    .PARAMETER Server2
    Fallback Server IP Address (or DNS name)

    .PARAMETER SslVersion
    LDAPS TLS/SSL version. It's not recommended to use version older than 1.2!

    .PARAMETER Tfa
    Use Two-factor authentication

    .PARAMETER UserAttr
    LDAP user attribute name

    .PARAMETER Verify
    Verify the server's SSL certificate

    .EXAMPLE
    Update-Realm -Realm "proxmox2"

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]
        $Realm,
        [Parameter(Mandatory = $True)]
        [ValidateSet('ad', 'ldap', 'pam', 'pve')]
        [string]
        $Type,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('\w+=[^,]+(,\s*\w+=[^,]+)*')]
        [string]
        $BaseDn,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('\w+=[^,]+(,\s*\w+=[^,]+)*')]
        [string]
        $BindDn,
        [Parameter(Mandatory = $False)]
        [string]
        $CaPath, # Defaults to '/etc/ssl/certs'
        [Parameter(Mandatory = $False)]
        [string]
        $Cert,
        [Parameter(Mandatory = $False)]
        [string]
        $CertKey,
        [Parameter(Mandatory = $False)]
        [string]
        $Comment,
        [Parameter(Mandatory = $False)]
        [switch]
        $Default,
        [Parameter(Mandatory = $False)]
        [string]
        $Delete,
        [Parameter(Mandatory = $False)]
        [string]
        $Digest,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('\S+')]
        [string]
        $Domain,
        [Parameter(Mandatory = $False)]
        [ValidateRange(1, 65535)]
        [int]
        $Port,
        [Parameter(Mandatory = $False)]
        [switch]
        $Secure,
        [Parameter(Mandatory = $False)]
        [string]
        $Server1,
        [Parameter(Mandatory = $False)]
        [string]
        $Server2,
        [Parameter(Mandatory = $False)]
        [ValidateSet('tlsv1', 'tlsv1_1', 'tlsv1_2', 'tlsv1_3')]
        [string]
        $SslVersion,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('(type=[a-zA-Z0-9]+)(,digits=[0-9]+)?(,id=[a-zA-Z0-9]+)?(,key=[a-zA-Z0-9]+)?(,step=[0-9]+)?(,url=((http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?))?')]
        [string]
        $Tfa,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('\S{2,}')]
        [string]
        $UserAttr,
        [Parameter(Mandatory = $False)]
        [switch]
        $Verify
    )
    $Options = @()
    $Options.Add('realm', $Realm)
    $Options.Add('type', $Type)
    # string
    if ($CaPath -and -not [String]::IsNullOrEmpty($CaPath) -and -not [String]::IsNullOrWhiteSpace($CaPath)) { $Options.Add('capath', $CaPath) }
    if ($Cert -and -not [String]::IsNullOrEmpty($Cert) -and -not [String]::IsNullOrWhiteSpace($Cert)) { $Options.Add('cert', $Cert) }
    if ($CertKey -and -not [String]::IsNullOrEmpty($CertKey) -and -not [String]::IsNullOrWhiteSpace($CertKey)) { $Options.Add('certkey', $CertKey) }
    if ($Comment -and -not [String]::IsNullOrEmpty($Comment) -and -not [String]::IsNullOrWhiteSpace($Comment)) { $Options.Add('comment', $Comment) }
    if ($Delete -and -not [String]::IsNullOrEmpty($Delete) -and -not [String]::IsNullOrWhiteSpace($Delete)) { $Options.Add('delete', $Delete) }
    if ($Digest -and -not [String]::IsNullOrEmpty($Digest) -and -not [String]::IsNullOrWhiteSpace($Digest)) { $Options.Add('digest', $Digest) }
    if ($Server1 -and -not [String]::IsNullOrEmpty($Server1) -and -not [String]::IsNullOrWhiteSpace($Server1)) { $Options.Add('server1', $Server1) }
    if ($Server2 -and -not [String]::IsNullOrEmpty($Server2) -and -not [String]::IsNullOrWhiteSpace($Server2)) { $Options.Add('server2', $Server2) }
    # integer
    if ($Port -and -not [String]::IsNullOrEmpty($Port) -and -not [String]::IsNullOrWhiteSpace($Port)) { $Options.Add('port', $Port) }
    # enum
    if ($SslVersion -and -not [String]::IsNullOrEmpty($SslVersion) -and -not [String]::IsNullOrWhiteSpace($SslVersion)) { $Options.Add('sslversion', $SslVersion) }
    # regex string
    if ($BaseDn -and -not [String]::IsNullOrEmpty($BaseDn) -and -not [String]::IsNullOrWhiteSpace($BaseDn)) { $Options.Add('base_dn', $BaseDn) }
    if ($BindDn -and -not [String]::IsNullOrEmpty($BindDn) -and -not [String]::IsNullOrWhiteSpace($BindDn)) { $Options.Add('bind_dn', $BindDn) }
    if ($Domain -and -not [String]::IsNullOrEmpty($Domain) -and -not [String]::IsNullOrWhiteSpace($Domain)) { $Options.Add('domain', $Domain) }
    if ($Tfa -and -not [String]::IsNullOrEmpty($Tfa) -and -not [String]::IsNullOrWhiteSpace($Tfa)) { $Options.Add('tfa', $Tfa) }
    if ($UserAttr -and -not [String]::IsNullOrEmpty($UserAttr) -and -not [String]::IsNullOrWhiteSpace($UserAttr)) { $Options.Add('user_attr', $UserAttr) }
    # boolean
    if ($Default) { $Options.Add('default', $Default) }
    if ($Secure) { $Options.Add('secure', $Secure) }
    if ($Verify) { $Options.Add('verify', $Verify) }
    Invoke-ProxmoxAPI -Method Put -Resource "access/domains" -Options $Options
}

function Update-Realm {
    <#
    .SYNOPSIS
    Update authentication server settings

    .DESCRIPTION
    Update authentication server settings

    .PARAMETER Realm
    Authentication domain ID

    .PARAMETER BaseDn
    LDAP base domain name

    .PARAMETER BindDn
    LDAP bind domain name

    .PARAMETER CaPath
    Path to the CA certificate store

    .PARAMETER Cert
    Path to the client certificate

    .PARAMETER CertKey
    Path to the client certificate key

    .PARAMETER Comment
    Description

    .PARAMETER Default
    Use this as default realm

    .PARAMETER Delete
    A list of settings you want to delete

    .PARAMETER Digest
    Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.

    .PARAMETER Domain
    AD domain name

    .PARAMETER Port
    Server Port

    .PARAMETER Secure
    Use secure LDAPS protocol

    .PARAMETER Server1
    Server IP Address (or DNS name)

    .PARAMETER Server2
    Fallback Server IP Address (or DNS name)

    .PARAMETER SslVersion
    LDAPS TLS/SSL version. It's not recommended to use version older than 1.2!

    .PARAMETER Tfa
    Use Two-factor authentication

    .PARAMETER UserAttr
    LDAP user attribute name

    .PARAMETER Verify
    Verify the server's SSL certificate

    .EXAMPLE
    Update-Realm -Realm "proxmox2"

    .NOTES
    General notes
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage("PSUseShouldProcessForStateChangingFunctions", Scope = "function")]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]
        $Realm,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('\w+=[^,]+(,\s*\w+=[^,]+)*')]
        [string]
        $BaseDn,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('\w+=[^,]+(,\s*\w+=[^,]+)*')]
        [string]
        $BindDn,
        [Parameter(Mandatory = $False)]
        [string]
        $CaPath, # Defaults to '/etc/ssl/certs'
        [Parameter(Mandatory = $False)]
        [string]
        $Cert,
        [Parameter(Mandatory = $False)]
        [string]
        $CertKey,
        [Parameter(Mandatory = $False)]
        [string]
        $Comment,
        [Parameter(Mandatory = $False)]
        [switch]
        $Default,
        [Parameter(Mandatory = $False)]
        [string]
        $Delete,
        [Parameter(Mandatory = $False)]
        [string]
        $Digest,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('\S+')]
        [string]
        $Domain,
        [Parameter(Mandatory = $False)]
        [ValidateRange(1, 65535)]
        [int]
        $Port,
        [Parameter(Mandatory = $False)]
        [switch]
        $Secure,
        [Parameter(Mandatory = $False)]
        [string]
        $Server1,
        [Parameter(Mandatory = $False)]
        [string]
        $Server2,
        [Parameter(Mandatory = $False)]
        [ValidateSet('tlsv1', 'tlsv1_1', 'tlsv1_2', 'tlsv1_3')]
        [string]
        $SslVersion,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('(type=[a-zA-Z0-9]+)(,digits=[0-9]+)?(,id=[a-zA-Z0-9]+)?(,key=[a-zA-Z0-9]+)?(,step=[0-9]+)?(,url=((http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?))?')]
        [string]
        $Tfa,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('\S{2,}')]
        [string]
        $UserAttr,
        [Parameter(Mandatory = $False)]
        [switch]
        $Verify
    )
    $Options = @()
    # string
    if ($CaPath -and -not [String]::IsNullOrEmpty($CaPath) -and -not [String]::IsNullOrWhiteSpace($CaPath)) { $Options.Add('capath', $CaPath) }
    if ($Cert -and -not [String]::IsNullOrEmpty($Cert) -and -not [String]::IsNullOrWhiteSpace($Cert)) { $Options.Add('cert', $Cert) }
    if ($CertKey -and -not [String]::IsNullOrEmpty($CertKey) -and -not [String]::IsNullOrWhiteSpace($CertKey)) { $Options.Add('certkey', $CertKey) }
    if ($Comment -and -not [String]::IsNullOrEmpty($Comment) -and -not [String]::IsNullOrWhiteSpace($Comment)) { $Options.Add('comment', $Comment) }
    if ($Delete -and -not [String]::IsNullOrEmpty($Delete) -and -not [String]::IsNullOrWhiteSpace($Delete)) { $Options.Add('delete', $Delete) }
    if ($Digest -and -not [String]::IsNullOrEmpty($Digest) -and -not [String]::IsNullOrWhiteSpace($Digest)) { $Options.Add('digest', $Digest) }
    if ($Server1 -and -not [String]::IsNullOrEmpty($Server1) -and -not [String]::IsNullOrWhiteSpace($Server1)) { $Options.Add('server1', $Server1) }
    if ($Server2 -and -not [String]::IsNullOrEmpty($Server2) -and -not [String]::IsNullOrWhiteSpace($Server2)) { $Options.Add('server2', $Server2) }
    # integer
    if ($Port -and -not [String]::IsNullOrEmpty($Port) -and -not [String]::IsNullOrWhiteSpace($Port)) { $Options.Add('port', $Port) }
    # enum
    if ($SslVersion -and -not [String]::IsNullOrEmpty($SslVersion) -and -not [String]::IsNullOrWhiteSpace($SslVersion)) { $Options.Add('sslversion', $SslVersion) }
    # regex string
    if ($BaseDn -and -not [String]::IsNullOrEmpty($BaseDn) -and -not [String]::IsNullOrWhiteSpace($BaseDn)) { $Options.Add('base_dn', $BaseDn) }
    if ($BindDn -and -not [String]::IsNullOrEmpty($BindDn) -and -not [String]::IsNullOrWhiteSpace($BindDn)) { $Options.Add('bind_dn', $BindDn) }
    if ($Domain -and -not [String]::IsNullOrEmpty($Domain) -and -not [String]::IsNullOrWhiteSpace($Domain)) { $Options.Add('domain', $Domain) }
    if ($Tfa -and -not [String]::IsNullOrEmpty($Tfa) -and -not [String]::IsNullOrWhiteSpace($Tfa)) { $Options.Add('tfa', $Tfa) }
    if ($UserAttr -and -not [String]::IsNullOrEmpty($UserAttr) -and -not [String]::IsNullOrWhiteSpace($UserAttr)) { $Options.Add('user_attr', $UserAttr) }
    # boolean
    if ($Default) { $Options.Add('default', $Default) }
    if ($Secure) { $Options.Add('secure', $Secure) }
    if ($Verify) { $Options.Add('verify', $Verify) }
    Invoke-ProxmoxAPI -Method Put -Resource "access/domains/$Realm" -Options $Options
}

function Remove-Realm {
    <#
    .SYNOPSIS
    Delete an authenication server

    .DESCRIPTION
    Delete an authenication server

    .PARAMETER Realm
    Authentication domain ID

    .EXAMPLE
    Delete-Realm -Realm "proxmox-realm"

    .NOTES
    General notes
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage("PSUseShouldProcessForStateChangingFunctions", Scope = "function")]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]
        $Realm
    )
    Invoke-ProxmoxAPI -Method Delete -Resource "access/domains/$Realm"
}

Export-ModuleMember -Cmdlet @(
    'Request-Ticket',
    'Get-Realm',
    'Remove-Realm',
    'Update-Realm'
)