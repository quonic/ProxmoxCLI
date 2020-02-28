function Get-Pool {
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