##################################################################
# Module Manifest Name: Apps.CPS.PowerShell.Network.psm1
# Module Manifest Description: Holds Network related functions
# Author: Srinath Sadda
#################################################################

<#
    .SYNOPSIS
        CPS Network Module.
    .DESCRIPTION
        Holds Network related functions.
    .EXAMPLE
        Import-Module -Name .\Apps.CPS.PowerShell.psd1
    .NOTES
        Module Name: Apps.CPS.PowerShell.Network.psm1
        Module Description: Holds Network related functions.
        Author: Srinath Sadda
    .LINK
#>

Function Get-CPSDCNetFirewallProfile {
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
            Import-Module -Name NetSecurity -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
            $DomainControllers = Get-ADDomainController -Filter * | Select-Object HostName
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
    }

    Process {
        ForEach ($DomainController in $DomainControllers) {
            Try {
			    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSDCNetFirewallProfile] [Get-NetFirewallProfile] Getting network profile information for domain controller [$($DomainController.HostName)]..."
                $NetFirewallProfiles = Get-NetFirewallProfile -CimSession $DomainController.HostName
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSDCNetFirewallProfile] [Get-Service] Getting Windows firewall status for domain controller [$($DomainController.HostName)]..."
                $MpsSvcStatus = Get-Service -ComputerName $DomainController.HostName | Where-Object {$_.Name -match "MpsSvc"}
                ForEach ($NetFirewallProfile in $NetFirewallProfiles) {
                    New-Object -TypeName PSObject -Property @{
                        Computer = [String] $DomainController.HostName
                        WindowsFirewallStatus = [String] $MpsSvcStatus.Status
                        FirewallProfile = [String] $NetFirewallProfile.Name
                        IsFirewallProfileEnabled = [Bool] $NetFirewallProfile.Enabled
                    }
                }
            }
		    Catch {
			    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                New-Object -TypeName PSObject -Property @{
                    Computer = [String] $Server
                    WindowsFirewallStatus = [String] $Null
                    FirewallProfile = [String] $Null
                    IsFirewallProfileEnabled = [Bool] $Null
                }
		    }
        }
    }

    End {
        [System.GC]::Collect()
    }
}

Function Get-CPSNetFirewallProfile {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("CC","EC","MC")]
        [String] $ClusterType,

        [Parameter(
            Position = 1,
            Mandatory = $False,
            HelpMessage = "Specify maximum no. of threads. Default is 4 threads. Maximum is 8 threads:"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,8)]
        [Int16] $MaxThreads
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
            Import-Module -Name VirtualMachineManager -Verbose:$False
            Import-Module -Name NetSecurity -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        $Servers = @()

        Try {
            #region Get-CPSVMMOwnerNode
            $VMMServer = Get-CPSVMMOwnerNode
            #endregion
        
            #region Get-SCVMHost
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSNetFirewallProfile] [Get-SCVMHost] Getting virtual machine hosts for cluster type [$ClusterType]..."
            $VMHosts = Get-SCVMHost -VMMServer $VMMServer | Select-Object FullyQualifiedDomainName,HostCluster | Where-Object {$_.HostCluster -like "*$ClusterType*"}
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSNetFirewallProfile] Identified $($VMHosts.Count) virtual machine hosts."
            #endregion

            #region Get-SCVirtualMachine
            ForEach ($VMHost in $VMHosts) {
	            $Servers += $($VMHost.FullyQualifiedDomainName)
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSNetFirewallProfile] [Get-SCVirtualMachine] Getting virtual machines from host [$($VMHost.FullyQualifiedDomainName)]..."
                $VirtualMachines = Get-SCVirtualMachine -VMHost $($VMHost.FullyQualifiedDomainName) | Select-Object Name | ForEach-Object {$_.Name}
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSNetFirewallProfile] Identified $($VirtualMachines.Count) virtual machines."
	            $Servers += $VirtualMachines
            }
            #endregion
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        #region Script Block
        $ScriptBlock = {
            [CmdletBinding()]
            Param (       
                [Parameter(
                    Position = 0,
                    Mandatory = $True
                )]
                [ValidateNotNullOrEmpty()]
                [String] $Server
            )

            Try {
                $SaveVerbosePreference = $VerbosePreference
                $VerbosePreference = "SilentlyContinue"
                Import-Module -Name NetSecurity -Verbose:$False
                $VerbosePreference = $SaveVerbosePreference
            }
            Catch {
                Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
            }
		    
            Try {
			    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSNetFirewallProfile] [Get-NetFirewallProfile] Getting network profile information for server [$Server]..."
                $NetFirewallProfiles = Get-NetFirewallProfile -CimSession $Server
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSNetFirewallProfile] [Get-Service] Getting Windows firewall status for server [$Server]..."
                $MpsSvcStatus = Get-Service -ComputerName $Server | Where-Object {$_.Name -match "MpsSvc"}
                ForEach ($NetFirewallProfile in $NetFirewallProfiles) {
                    New-Object -TypeName PSObject -Property @{
                        Computer = [String] $Server
                        WindowsFirewallStatus = [String] $MpsSvcStatus.Status
                        FirewallProfile = [String] $NetFirewallProfile.Name
                        IsFirewallProfileEnabled = [Bool] $NetFirewallProfile.Enabled
                    }
                }
		    }
		    Catch {
			    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                New-Object -TypeName PSObject -Property @{
                    Computer = [String] $Server
                    WindowsFirewallStatus = [String] $Null
                    FirewallProfile = [String] $Null
                    IsFirewallProfileEnabled = [Bool] $Null
                }
		    }
        }
        #endregion
    }

    Process {
        If ($PSBoundParameters['MaxThreads']) {
            If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose -Debug
            }
            ElseIf ($PSBoundParameters['Verbose']) {
                Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose
            }
            ElseIf ($PSBoundParameters['Debug']) {
                Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Debug
            }
            Else {
                Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance
            }
        }
        Else {
	        $I = 0
            [Array]::Sort($Servers)
	        ForEach ($Server in $Servers) {
                Try {
                    $I++
			        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSNetFirewallProfile] [Get-NetFirewallProfile] Getting network profile information for server [$Server]..."
                    $NetFirewallProfiles = Get-NetFirewallProfile -CimSession $Server
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSNetFirewallProfile] [Get-Service] Getting Windows firewall status for server [$Server]..."
                    $MpsSvcStatus = Get-Service -ComputerName $Server | Where-Object {$_.Name -match "MpsSvc"}
                    ForEach ($NetFirewallProfile in $NetFirewallProfiles) {
                        New-Object -TypeName PSObject -Property @{
                            Computer = [String] $Server
                            WindowsFirewallStatus = [String] $MpsSvcStatus.Status
                            FirewallProfile = [String] $NetFirewallProfile.Name
                            IsFirewallProfileEnabled = [Bool] $NetFirewallProfile.Enabled
                        }
                    }
		        }
		        Catch {
			        Write-Error -Exception $_.Exception -Message $_.Exception.Message
                    New-Object -TypeName PSObject -Property @{
                        Computer = [String] $Server
                        WindowsFirewallStatus = [String] $Null
                        FirewallProfile = [String] $Null
                        IsFirewallProfileEnabled = [Bool] $Null
                    }
		        }
	        }
        }
    }

    End {
        [System.GC]::Collect()
    }
}