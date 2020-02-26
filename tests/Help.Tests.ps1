$projectRoot = Resolve-Path "$PSScriptRoot\.."
$script:ModuleName = 'ProxmoxCLI'

Describe "Help tests for $moduleName" -Tags Build {

    $functions = Get-Command -Module $moduleName
    $help = $functions | ForEach-Object { Get-Help $_.name }
    foreach ($node in $help) {
        Context $node.name {

            It "has a description" {
                $node.description | Should Not BeNullOrEmpty
            }
            It "has an example" {
                $node.examples | Should Not BeNullOrEmpty
            }
            foreach ($parameter in $node.parameters.parameter) {
                if ($parameter -notmatch 'whatif|confirm') {
                    It "parameter $($parameter.name) has a description" {
                        $parameter.Description.text | Should Not BeNullOrEmpty
                    }
                }
            }
        }
    }
}

