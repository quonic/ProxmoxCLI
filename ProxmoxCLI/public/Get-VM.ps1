function Get-VM {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    [OutputType([PSObject[]])]
    param(
        # Id of the Qemu guest
        [Parameter(Mandatory = $false, ParameterSetName = "Id", ValueFromPipelineByPropertyName)]
        [string[]]
        $Id,
        # Node(s) that the Qemu guest(s) are running under
        [Parameter(Mandatory = $false, ParameterSetName = "Id", ValueFromPipelineByPropertyName)]
        [int[]]
        $Node
    )
    
    begin {
    }
    
    process {
        if ($Node) {
            $Node | ForEach-Object {
                if ($Id) {
                    Get-NodeQemu -node $_ | Where-Object { $_ -in $Id }
                }
                else {
                    Get-NodeQemu -node $_
                }
            }
        }
        else {
            Get-Node | ForEach-Object {
                Get-NodeQemu -node $_.node        
            }
        }
    }
    
    end {
    }
}