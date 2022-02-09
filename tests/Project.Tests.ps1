$projectRoot = Resolve-Path "$PSScriptRoot\.."
$script:ModuleName = 'ProxmoxCLI'
$moduleRoot = "$projectRoot\$ModuleName"

Describe "PSScriptAnalyzer rule-sets" -Tag Build {

    $Rules = Get-ScriptAnalyzerRule
    $scripts = Get-ChildItem $moduleRoot -Include *.ps1, *.psm1, *.psd1 -Recurse | Where-Object fullname -notmatch 'classes'

    foreach ( $Script in $scripts ) {
        Context "Script '$($script.FullName)'" {

            foreach ( $rule in $rules ) {
                $results = Invoke-ScriptAnalyzer -Path $script.FullName -IncludeRule $rule.RuleName | Format-List *
                It "Rule [$rule]" {
                    $results.Count | Should -Be 0
                }
            }
        }
    }
}


Describe "General project validation: $moduleName" -Tags Build {

    It "Module '$moduleName' can import cleanly" {
        { Import-Module (Join-Path $moduleRoot "$moduleName.psm1") -force } | Should -Not -Throw
    }
}
