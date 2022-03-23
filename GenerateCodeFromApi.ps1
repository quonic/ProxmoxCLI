[CmdletBinding()]
param(
    [switch]
    $Test
)
function Get-ApiChild {
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]
        $Child,
        $ParantPath
    )
    if ($Child.text.Count -gt 1) {
        for ($i = 0; $i -lt $Child.text.Count; $i++) {
            [PSCustomObject]@{
                Name     = $Child.text[$i]
                Path     = $Child.path[$i]
                Children = $Child.children[$i] | Where-Object { $_.path -like "$ParantPath*" } | ForEach-Object { $(Get-ApiChild -Child $_ -ParantPath $Child.path[$i]) }
                Methods  = if ($Child.info[$i]) { $(Get-ApiInfo -Info $Child.info[$i]) }else { $null }
            }
        }
    }
    else {
        $Child.text | ForEach-Object {
            [PSCustomObject]@{
                Name     = $Child.text
                Path     = $Child.path
                Children = if ($Child.children) { $(Get-ApiChild -Child $Child.children -ParantPath $Child.path) }else { $null }
                Methods  = if ($Child.info) { $(Get-ApiInfo -Info $Child.info) }else { $null }
            }
        }
    }
}

function Get-ApiProperties {
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $Properties
    )
    ($Properties | Get-Member -MemberType NoteProperty).Name | ForEach-Object {
        $Name = $_
        if ($Name -like "remove" -or $Name -like "address") {
            [PSCustomObject]@{
                Name        = $Name
                Required    = if (($Properties | Select-Object -ExpandProperty $_).optional -eq 1) { $false } else { $true }
                Type        = ($Properties | Select-Object -ExpandProperty $_).type
                Description = ($Properties | Select-Object -ExpandProperty $_).description
                Format      = ($Properties | Select-Object -ExpandProperty $_).format
            }
        }
        else {
            [PSCustomObject]@{
                Name        = $Name
                Required    = if ($Properties."$Name".optional -eq 1) { $false } else { $true }
                Type        = $Properties."$Name".type
                Description = $Properties."$Name".description
                Format      = $Properties."$Name".format
            }
        }
    }
}

function Get-ApiInfo {
    param (
        $Info,
        $Path
    )
    $Info | ForEach-Object {
        if ($_.GET) {
            [PSCustomObject]@{
                Name        = $_.GET.name
                Method      = $_.GET.method
                Description = $_.GET.description
                Parameters  = if ($_.GET.parameters.properties) { Get-ApiProperties -Properties $_.GET.parameters.properties }else { $null }
                # Permissions = $_.GET.permissions # Probably not needed
                Returns     = $_.GET.returns
            }
        }
        if ($_.POST) {
            [PSCustomObject]@{
                Name        = $_.POST.name
                Method      = $_.POST.method
                Description = $_.POST.description
                Parameters  = if ($_.POST.parameters.properties) { Get-ApiProperties -Properties $_.POST.parameters.properties }else { $null }
                # Permissions = $_.POST.permissions # Probably not needed
                Returns     = $_.POST.returns
            }
        }
        if ($_.PUT) {
            [PSCustomObject]@{
                Name        = $_.PUT.name
                Method      = $_.PUT.method
                Description = $_.PUT.description
                Parameters  = if ($_.PUT.parameters.properties) { Get-ApiProperties -Properties $_.PUT.parameters.properties }else { $null }
                # Permissions = $_.PUT.permissions # Probably not needed
                Returns     = $_.PUT.returns
            }
        }
        if ($_.DELETE) {
            [PSCustomObject]@{
                Name        = $_.DELETE.name
                Method      = $_.DELETE.method
                Description = $_.DELETE.description
                Parameters  = if ($_.DELETE.parameters.properties) { Get-ApiProperties -Properties $_.DELETE.parameters.properties }else { $null }
                # Permissions = $_.DELETE.permissions # Probably not needed
                Returns     = $_.DELETE.returns
            }
        }
        if ($_.PATCH) {
            [PSCustomObject]@{
                Name        = $_.PATCH.name
                Method      = $_.PATCH.method
                Description = $_.PATCH.description
                Parameters  = if ($_.PATCH.parameters.properties) { Get-ApiProperties -Properties $_.PATCH.parameters.properties }else { $null }
                # Permissions = $_.PATCH.permissions # Probably not needed
                Returns     = $_.PATCH.returns
            }
        }
    }
}

function Build-Api {
    param (
        [Parameter(Mandatory)]
        $Data
    )
    Build-ApiCmdlets -Data $Data -Recursive
}
function Build-ApiCmdlets {
    param (
        [Parameter(Mandatory)]
        $Data,
        [switch]
        $Recursive
    )
    $Data | ForEach-Object {
        $Name = $_.Name
        $Path = (($_.Path -split '/') |
            ForEach-Object {
                if ($_ -and -not [string]::IsNullOrEmpty($_) -and -not [string]::IsNullOrWhiteSpace($_)) {
                    $curName = (Get-Culture).TextInfo.ToTitleCase($_) -replace '_' -replace '-' -replace '{' -replace '}'
                    if ($curName -notlike "*id" -and $curName -notlike "id") {
                        $curName
                    }
                    
                }
            }
        )

        if ($Path[1] -and ($Path[0] -replace ".{1}$") -like $Path[1]) {
            $Path[0] = $Path[0] -replace ".{1}$"
        }

        $FormattedName = ($Path | Select-Object -Unique) -join ''
        $NewPath = $_.Path

        $_.Methods | ForEach-Object {
            $TitleCaseName = $((Get-Culture).TextInfo.ToTitleCase($Name) -replace '_' -replace '-' -replace '{' -replace '}')

            $Noun = if ($FormattedName -like "*$TitleCaseName") {
                "$($FormattedName)"
            }
            else {
                "$($FormattedName)$($TitleCaseName)"
            }
            
            $Verb = switch ($_.Method) {
                "GET" { "Get" ; break }
                "POST" { "New" ; break }
                "PUT" { "Set" ; break }
                "DELETE" { "Remove" ; break }
                "PATCH" { "Update"; break }
                Default {
                    if ($_.Method -and [string]::IsNullOrEmpty($_.Method) -and [string]::IsNullOrWhiteSpace($_.Method)) {
                        Write-Warning -Message "Method: $($_.Method) not implimented"
                    }
                }
            }
            
            if ($Verb -and -not [string]::IsNullOrEmpty($Verb) -and -not [string]::IsNullOrWhiteSpace($Verb) -and "$Verb-$Noun" -notlike "New-AccessTicket") {

                "function $Verb-$Noun `{"
                "`t[CmdletBinding()]"
                # Create OutputType
                if ($_.Returns -and $_.Returns.type) {
                    switch ($_.Returns.type) {
                        "null" {  }
                        "array" { "`t[OutputType([PSCustomObject[]])]" }
                        "string" { "`t[OutputType([string])]" }
                        "integer" { "`t[OutputType([Int32])]" }
                        "object" { "`t[OutputType([PSCustomObject])]" }
                    }
                }
                "`tparam("
                if ($_.Parameters) {
                    # Create param block

                    # Create parameters
                    $Params = $_.Parameters | ForEach-Object {
                        if (
                            $_.Name -and
                            -not [string]::IsNullOrEmpty($_.Name) -and
                            -not [string]::IsNullOrWhiteSpace($_.Name) -and
                            $_.Name -notin $("debug", "verbose", "force") # Exlude reserved common parameters
                        ) {
                            
                            if ($_.Required) {
                                "`t`t[Parameter(Mandatory)]"
                            }
                            if ($_.Format -and $_.Format -isnot [String]) {
                                $_.Format | Get-Member -MemberType NoteProperty | ForEach-Object {
                                    if ($_.pattern) {
                                        "`t`t[ValidatePattern(""$($_.pattern)"")]"
                                    }
                                    if ($_.minimum -and $_.maximum) {
                                        "`t`t[ValidateRange($($_.minimum), $($_.maximum))]"
                                    }
                                    elseif ($_.minimum -and -not $_.maximum) {
                                        "`t`t[ValidateRange($($_.minimum), $([Int32]::MaxValue))]"
                                    }
                                    elseif (-not $_.minimum -and $_.maximum) {
                                        "`t`t[ValidateRange(0, $($_.maximum))]"
                                    }
                                    if ($_.format_description) {
                                        "# Format: $($_.format_description)"
                                    }
                                    $_ | Select-Object -Property format, type
                                }
                            }
                            if ($($_.Name -replace '-') -match ".+\[n\]") {
                                $pDesc = $_.Description
                                if ($_.Type -like "boolean") {
                                    $pType = "switch"
                                }
                                else {
                                    $pType = $_.Type
                                }
                                
                                $pName = $_.Name -replace '-'
                                switch ($pName) {
                                    'acmedomain[n]' {
                                        0..10 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'hostpci[n]' { 
                                        0..10 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'ide[n]' {
                                        0..3 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'ipconfig[n]' {
                                        0..10 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'link[n]' {
                                        0..7 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'mp[n]' {
                                        0..10 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'net[n]' {
                                        0..10 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'numa[n]' {
                                        0..10 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'parallel[n]' {
                                        0..2 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'sata[n]' {
                                        0..5 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'scsi[n]' {
                                        0..30 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'serial[n]' {
                                        0..3 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'unused[n]' {}
                                    'usb[n]' {
                                        0..4 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    'virtio[n]' {
                                        0..15 | ForEach-Object {
                                            "`t`t# $(($pDesc -split "`n")[0])"
                                            "`t`t[$($pType)]"
                                            "`t`t`$$($pName -replace "\[n\]")$_,"
                                        }
                                    }
                                    Default {}
                                }
                            }
                            else {
                                "`t`t# $(($_.Description -split "`n")[0])"
                                "`t`t# $(($_.Format -split "`n")[0])"
                                if ($_.Type -like "boolean") {
                                    "`t`t[switch]"
                                }
                                elseif ($_.Name -like "*password*") {
                                    "`t`t[securestring]"
                                }
                                else {
                                    "`t`t[$($_.Type)]"
                                }
                                if ($_.Name -like "args") {
                                    "`t`t`$args,"
                                }
                                else {
                                    "`t`t`$$($_.Name -replace '-'),"
                                }
                                
                            }
                        }
                    }
                    if ($Params) {
                        ($Params -join "`n").TrimEnd(',')
                        # Figure out what params are need in the path/uri
                        $ParamUri = ($_.Parameters | Where-Object { $Path -like "{$($_.Name)}" }).Name
                
                        $ParamUri | ForEach-Object {
                            # $PathParams = $null
                            # $PathParams = $NewPath -split "/" | Where-Object { $_ -like "{*}" } | ForEach-Object { $_ -replace "{$($_)}", "$($_ -replace '_')" }
                            $NewPath = $NewPath -replace "{$($_)}", "`$$($_ -replace '_')"
                        }
                    }
                
                    "`t)"
                    # Add required to $Options and skip any in the path/uri
                    $OptionsList = ""
                    $_.Parameters | Where-Object { $_.Required -and $Path -match "{$($_.Name)}" } | ForEach-Object {
                        $OptionsList += "`t`$Options.Add('$($_.Name)', `$$($_.Name -replace '-'))"
                    }
                    if ($OptionsList) {
                        # Init $Options array if there are options to use
                        "`t`$Options = @()"
                        $OptionsList
                    }
                    # Add optional params to $Options
                    $_.Parameters | Where-Object { -not $_.Required } | ForEach-Object {
                        if ($($_.Name -replace '-') -match ".+\[n\]") {
                            $pName = $_.Name -replace '-'
                            switch ($pName) {
                                'acmedomain[n]' {
                                    0..10 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'hostpci[n]' { 
                                    0..10 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'ide[n]' {
                                    0..3 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'ipconfig[n]' {
                                    0..10 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'link[n]' {
                                    0..7 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'mp[n]' {
                                    0..10 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'net[n]' {
                                    0..10 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'numa[n]' {
                                    0..10 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'parallel[n]' {
                                    0..2 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'sata[n]' {
                                    0..5 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'scsi[n]' {
                                    0..30 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'serial[n]' {
                                    0..3 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'unused[n]' {}
                                'usb[n]' {
                                    0..4 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                'virtio[n]' {
                                    0..15 | ForEach-Object {
                                        "`tif (`$$($pName -replace "\[n\]")$_ -and -not [String]::IsNullOrEmpty(`$$($pName -replace "\[n\]")$_) -and -not [String]::IsNullOrWhiteSpace(`$$($pName -replace "\[n\]")$_)) { `$Options.Add('$($pName -replace "\[n\]")$_',`$$($pName -replace "\[n\]")$_) }"
                                    }
                                }
                                Default {}
                            }
                        }
                        else {
                            if ($_.Type -like "boolean") {
                                # Handle booleans
                                "`tif (`$$($_.Name -replace '-')) { `$Options.Add('$($_.Name)', `$$($_.Name -replace '-')) }"
                            }
                            elseif ($_.Name -like "*password*") {
                                # Handle password parameters
                                "`tif (`$$($_.Name -replace '-')) { `$Options.Add('$($_.Name)', `$(`$$($_.Name -replace '-') | ConvertFrom-SecureString -AsPlainText)) }"
                            }
                            elseif ($_.Name -like "args") {
                                # Handle args
                                "`tif (`$args -and -not [String]::IsNullOrEmpty(`$args) -and -not [String]::IsNullOrWhiteSpace(`$args)) { `$Options.Add('$($_.Name)', `$args) }"
                            }
                            else {
                                "`tif (`$$($_.Name -replace '-') -and -not [String]::IsNullOrEmpty(`$$($_.Name -replace '-')) -and -not [String]::IsNullOrWhiteSpace(`$$($_.Name -replace '-'))) { `$Options.Add('$($_.Name)', `$$($_.Name -replace '-')) }"
                            }
                        }
                    }
                    # Invoke API call
                    if ($OptionsList) {
                        "`tInvoke-ProxmoxAPI -Method $($_.Method) -Resource `"$($NewPath -replace "{","$" -replace "}")`" -Options `$Options"
                    }
                    else {
                        "`tInvoke-ProxmoxAPI -Method $($_.Method) -Resource `"$($NewPath -replace "{","$" -replace "}")`""
                    }
                }
                else {
                    "`t)"
                    "`tInvoke-ProxmoxAPI -Method $($_.Method) -Resource `"$($NewPath -replace "{","$" -replace "}")`""
                }
                "}"
            }
        }
        if ($_.Children -and $Recursive) {
            Build-ApiCmdlets -Data $_.Children -Recursive
        }
    }
}

# Api descrition file
$apidataurl = "https://raw.githubusercontent.com/proxmox/pve-docs/master/api-viewer/apidata.js"

# Get apidata.js
$data = Invoke-WebRequest -Uri $apidataurl
# Split into an array of strings
$d = $data.Content -split "`n"
# Remove javascript code
$d[0] = $d[0] -replace "const apiSchema \= \[", "["
# Join everything back together
$json = $d[0..($d.Count - 4)] -join "`r`n"
# Convert from json and Loop through each parent object
$api = $json | ConvertFrom-Json | ForEach-Object {
    # Create each child object
    Get-ApiChild -Child $_
}

$ScriptPath = "./ProxmoxCLI/private/Api.ps1"
# Remove current Api.ps1
Remove-Item -Path $ScriptPath
# Build Api.ps1 from child object
Build-Api -Data $api | Out-File -FilePath $ScriptPath -Force

# Add module members via Export-ModuleMember
# $functionList = (Select-String -Path $ScriptPath -Pattern "function " -Raw) -replace "function ", "`t'" -replace " \{", "'`n"
# $ExportMemberList = "Export-ModuleMember -Function @(`n" + $($functionList) + "`n)"
# $ExportMemberList | Out-File -FilePath $ScriptPath -Append -Force