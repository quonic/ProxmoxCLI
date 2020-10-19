function Update-API {
    <#
    .SYNOPSIS
    Example synosis here

    .DESCRIPTION
    Example description here

    .PARAMETER ExampleRequired
    Example Required

    .PARAMETER ExamplePattern
    Example Pattern

    .PARAMETER ExampleString
    Example String

    .PARAMETER ExampleBoolean
    Example Boolean

    .PARAMETER ExampleInteger
    Example Integer

    .PARAMETER ExampleEnum
    Example Enum

    .EXAMPLE
    Update-API -ExamplePattern "example text"

    .NOTES
    General notes
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage("PSUseShouldProcessForStateChangingFunctions", Scope = "function")]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]
        $ExampleRequired,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('\w+=[^,]+(,\s*\w+=[^,]+)*')]
        [string]
        $ExamplePattern,
        [Parameter(Mandatory = $False)]
        [string]
        $ExampleString,
        [Parameter(Mandatory = $False)]
        [switch]
        $ExampleBoolean,
        [Parameter(Mandatory = $False)]
        [ValidateRange(1, 65535)]
        [int]
        $ExampleInteger,
        [Parameter(Mandatory = $False)]
        [ValidateSet('a', 'b')]
        [string]
        $ExampleEnum
    )
    $Options = @()
    # string
    if ($ExampleString -and -not [String]::IsNullOrEmpty($ExampleString) -and -not [String]::IsNullOrWhiteSpace($ExampleString)) { $Options.Add('ExampleString', $ExampleString) }
    # integer
    if ($ExampleInteger -and -not [String]::IsNullOrEmpty($ExampleInteger) -and -not [String]::IsNullOrWhiteSpace($ExampleInteger)) { $Options.Add('ExampleInteger', $ExampleInteger) }
    # enum
    if ($ExampleEnum -and -not [String]::IsNullOrEmpty($ExampleEnum) -and -not [String]::IsNullOrWhiteSpace($ExampleEnum)) { $Options.Add('ExampleEnum', $ExampleEnum) }
    # regex string
    if ($ExamplePattern -and -not [String]::IsNullOrEmpty($ExamplePattern) -and -not [String]::IsNullOrWhiteSpace($ExamplePattern)) { $Options.Add('ExamplePattern', $ExamplePattern) }
    # boolean
    if ($ExampleBoolean) { $Options.Add('example-boolean', $ExampleBoolean) }
    Invoke-ProxmoxAPI -Method Put -Resource "example/folder/$ExampleRequired" -Options $Options
}