################################################################
# Module Manifest Name: Apps.CPS.PowerShell.ActiveDirectory.psm1
# Module Manifest Description: Holds Active Directory related functions
# Author: Srinath Sadda
###############################################################

<#
    .SYNOPSIS
        CPS ActiveDirectory Module.
    .DESCRIPTION
        Holds Active Directory related functions.
    .EXAMPLE
        Import-Module -Name .\Apps.CPS.PowerShell.psd1
    .NOTES
        Module Name: Apps.CPS.PowerShell.ActiveDirectory.psm1
        Module Description: Holds Active Directory related functions.
        Author: Srinath Sadda
    .LINK
#>

Function Get-CPSADDomain {
    [CmdletBinding()]
    Param ()
    
    Begin {
        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }

        Try {
            $SaveVerbosePreference = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            Import-Module -Name ActiveDirectory -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
    }

    Process {
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSADDomain] [Get-ADDomain] Getting an Active Directory domain information..."
            $ADDomain = Get-ADDomain -ErrorAction Stop
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSADDomain] ADDomain: $($ADDomain | ConvertTo-Json)"
            Write-Output -InputObject $ADDomain
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
        }
    }

    End {
        [System.GC]::Collect()
    }
}

Function Get-CPSADDomainController {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False
        )]
        [Switch] $NextClosestSite
    )
    
    Begin {
        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }

        Try {
            $SaveVerbosePreference = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            Import-Module -Name ActiveDirectory -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
    }

    Process {
        Try {
            If ($NextClosestSite) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSADDomainController] [Get-ADDomainController] Getting an Active Directory discoverable domain controller information in the next closest site..."
                $ADDomainController = Get-ADDomainController -NextClosestSite -Discover -ErrorAction Stop
            }
            Else {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSADDomainController] [Get-ADDomainController] Getting one or more Active Directory domain controllers information..."
                $ADDomainController = Get-ADDomainController -Filter * -ErrorAction Stop
            }
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSADDomainController] ADDomainController: $($ADDomainController | ConvertTo-Json)"
            Write-Output -InputObject $ADDomainController
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
        }
    }

    End {
        [System.GC]::Collect()
    }
}

Function Get-CPSADUserPasswordExpiryTime {
    [CmdletBinding()]
    Param ()
    
    Begin {
        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }

        Try {
            $SaveVerbosePreference = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            $Env:ADPS_LoadDefaultDrive = 0 # Disable loading Active Directory module for Windows PowerShell with default drive 'AD' (effect the current user session only)
            Import-Module -Name ActiveDirectory -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
    }

    Process { 
        Try {
            $RootActivityId = $(Get-Date -Format "yyyymmss")
            $ActiveStepId = 0
            
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSADUserPasswordExpiryTime] [Get-ADUser] Getting one or more Active Directory users information..."
            $Users = Get-ADUser -Filter {(Enabled -eq $True) -and (PasswordNeverExpires -eq $False)} -Properties "SamAccountName","pwdLastSet","msDS-UserPasswordExpiryTimeComputed"
            $TotalSteps = $Users.Count
            
            ForEach ($User in $Users) {
                $ActiveStepId++
                Write-Progress -Activity "Getting User Accounts.." -Status "Processing User Account: $($User.SamAccountName) ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Identifying Password Expiry Time.."
                
                [DateTime] $PasswordLastSet = $([DateTime]::FromFileTime($User.pwdLastSet))
                [DateTime] $PasswordExpiryDate = $([DateTime]::FromFileTime($User.'msDS-UserPasswordExpiryTimeComputed'))
                $Days = ($PasswordExpiryDate - (Get-Date)).Days
                If ($Days -le 0) {
                    $IsExpired = $True
                }
                Else {
                    $IsExpired = $False
                }
                New-Object -TypeName PSObject -Property @{
                    SamAccountName = $User.SamAccountName
                    PasswordLastSet = $PasswordLastSet
                    PasswordExpiryDate = $PasswordExpiryDate
                    IsExpired = $IsExpired
                } | Select-Object SamAccountName,PasswordLastSet,PasswordExpiryDate,IsExpired
            }
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
        Write-Progress -Activity "Getting User Accounts.." -Status "Processing User Account: $($User.SamAccountName) ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Identifying Password Expiry Time.." -Completed
    }

    End {
        [System.GC]::Collect()
    }
}