function Get-Pool {
    <#
    .SYNOPSIS
    Returns the pool(s) configuration

    .DESCRIPTION
    Returns either a pool or multiple pools configuration

    .PARAMETER PoolId
    The Pool Id

    .EXAMPLE
    Get-Pool

    .EXAMPLE
    Get-Pool -PoolId "Pool1"

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Alias('id')]
        [string[]]
        $PoolId
    )
    if ($PoolId) {
        $PoolId | ForEach-Object {
            return (Invoke-ProxmoxAPI -Method Post -Resource "pools/$_")
        }
    }
    else {
        return (Invoke-ProxmoxAPI -Method Post -Resource "pools")
    }
}


Export-ModuleMember -Function @('Get-Pool')