function Get-Node {
    [CmdletBinding()]
    Param(
        # Parameter help description
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]
        $node
    )

    # TODO - Expand this to return more information, probably in Node class.
    if ($node) {
        return $node | ForEach-Object {
            New-Object -TypeName "Node" -ArgumentList $_
        }
    }
    else {
        return callGet -Resource "/nodes" | ForEach-Object {
            New-Object -TypeName "Node" -ArgumentList $_.node
        }
    }
}


Export-ModuleMember -Function @('Get-Node')