function Get-VMHost {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    [OutputType([PSObject[]])]
    param(
        # Name(s) of the host in the cluster
        [Parameter(Mandatory = $false, ParameterSetName = "Name", ValueFromPipelineByPropertyName)]
        [string[]]
        $Name
    )
    
    begin {
    }
    
    process {
        if ($Name) {
            $Name | ForEach-Object {
                $N = $_
                Get-Nodes | Where-Object { $_.Name -like $N }
            }
        }
        else {
            Get-Nodes
        }
    }
    
    end {
    }
}