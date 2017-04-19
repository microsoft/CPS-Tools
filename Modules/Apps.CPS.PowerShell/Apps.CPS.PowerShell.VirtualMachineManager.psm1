##################################################################
# Module Manifest Name: Apps.CPS.PowerShell.VirtualMachineManager.psm1
# Module Manifest Description: Holds VMM related functions
# Author: Srinath Sadda
#################################################################

<#
    .SYNOPSIS
        CPS Virtual Machine Manager Module.
    .DESCRIPTION
        Holds Virtual Machine Manager related functions.
    .EXAMPLE
        Import-Module -Name .\Apps.CPS.PowerShell.psd1
    .NOTES
        Module Name: Apps.CPS.PowerShell.VirtualMachineManager.psm1
        Module Description: Holds Virtual Machine Manager related functions.
        Author: Srinath Sadda
    .LINK
#>

Function Get-CPSVMMOwnerNode {
    [CmdletBinding()]
    Param (
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
            Import-Module -Name FailoverClusters -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
	}

	Process {
		Try {
			$VMMClusterName = "$($env:COMPUTERNAME.Split('-')[0])-CL-VMM"
			Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMOwnerNode] VMM Cluster Name: [$VMMClusterName]"
			
			$VMMClusterGroupName = "$($env:COMPUTERNAME.Split('-')[0])-HA-VMM"
			Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMOwnerNode] VMM Cluster Group Name: [$VMMClusterGroupName]"

			Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMOwnerNode] [Get-ClusterGroup] Identifying active owner node..."
			$VMMOwnerNode = (Get-ClusterGroup -Cluster $(Get-Cluster -Name $VMMClusterName) -Name $VMMClusterGroupName | Select-Object OwnerNode).OwnerNode.Name
			Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMOwnerNode] VMM Cluster Group Active Owner Node Name: [$VMMOwnerNode]"
            Write-Output -InputObject $VMMOwnerNode
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
	}

	End {
		[System.GC]::Collect()
	}
}

Function Get-CPSVMMComputerCertificateStatus {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [Alias("Credential")]
        [System.Management.Automation.PSCredential] $PSCredential
    )
	
    Begin {
		If ($PSBoundParameters['Verbose']) {
			$VerbosePreference = "Continue"
		}
		If ($PSBoundParameters['Debug']) {
			$DebugPreference = "Continue"
			$ConfirmPreference = "None"
		}
        
        $ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")

        #region VMM Owner Node
		Try {
            $VMMOwnerNode = Get-CPSVMMOwnerNode
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
        #endregion

        #region Script Block
        $ScriptBlock = {
            #region Script Block Computer Certificates
            $ScriptBlockComputerCertificates = {
                $VerbosePreference = "Continue"
                Try {
                    Set-Location Cert:\LocalMachine\My
                    $ComputerCertificates = Get-ChildItem | Where-Object {$_.FriendlyName -like 'SCVMM_CERTIFICATE_KEY_CONTAINER*'}
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] Found $($ComputerCertificates.Count) certificate(s)."
                    Write-Output -InputObject $ComputerCertificates
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                }
            }
            #endregion

            Try {
                $VerbosePreference = "Continue"
                Set-location Cert:\LocalMachine\TrustedPeople
                $SCVMMCertificates = Get-ChildItem
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] Found $($SCVMMCertificates.Count) certificate(s)."
            }
            Catch {
                Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
            }

            $RootActivityId = $(Get-Date -Format "yyyymmss")
            $ActiveStepId = 0
            $TotalSteps = $SCVMMCertificates.Count

            If ($SCVMMCertificates.count -gt 0) {
                $I = 0
                
                ForEach ($SCVMMCertificate in $SCVMMCertificates) {
                    $I++
                    $ActiveStepId++
                    Write-Progress -Activity "Getting Certificates.." -Status "Processing: $($($SCVMMCertificate.DnsNameList).Unicode) ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Certificate Information.."
                   
                    If ([System.Net.IPAddress]::TryParse($($SCVMMCertificate.DnsNameList).Unicode,[Ref] $Null) -eq $True) {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] Skipping IP address $($($SCVMMCertificate.DnsNameList).Unicode)..."
                        Continue
                    }
                    
                    If (($($SCVMMCertificate.DnsNameList).Unicode -like '*VMMWinPEAgentOSDBootstrap*') -or ($($SCVMMCertificate.DnsNameList).Unicode -like '*-CON-*') -or ($($SCVMMCertificate.DnsNameList).Unicode -like '*-VMM-*') -or ($($SCVMMCertificate.DnsNameList).Unicode -like '*HA-VMM*')) {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] Skipping computer [$($($SCVMMCertificate.DnsNameList).Unicode)]..."
                        Continue
                    }
                    
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] [Test-Connection] Connecting to computer [$($($SCVMMCertificate.DnsNameList).Unicode)] ($I of $($SCVMMCertificates.Count))..."
                    If (!(Test-Connection -ComputerName $($SCVMMCertificate.DnsNameList).Unicode -Count 1 -Quiet)) {
                        Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] Connecting to computer [$($($SCVMMCertificate.DnsNameList).Unicode)] failed!"
                        [HashTable] $HashTable = @{}
                        $HashTable.Add("Computer", $($SCVMMCertificate.DNSNameList).Unicode)
                        $HashTable.Add("SCVMMServer", $($env:COMPUTERNAME))
                        $HashTable.Add("IsCertificateMatched", $False)
                        $HashTable.Add("ComputerCertificateSerialNumber", $Null)
                        $HashTable.Add("SCVMMCertificateSerialNumber", $SCVMMCertificate.SerialNumber)
                        $HashTable.Add("ComputerCertificateSubjectName", $Null)
                        $HashTable.Add("SCVMMCertificateSubjectName", $SCVMMCertificate.SubjectName.Name)
                        $HashTable.Add("ComputerCertificateThumbprint", $Null)
                        $HashTable.Add("SCVMMCertificateThumbprint", $SCVMMCertificate.Thumbprint)
                        $HashTable.Add("ComputerCertificateNotAfter", $Null)
                        $HashTable.Add("SCVMMCertificateNotAfter", $SCVMMCertificate.NotAfter)
                        $HashTable.Add("ComputerCertificateNotBefore", $Null)
                        $HashTable.Add("SCVMMCertificateNotBefore", $SCVMMCertificate.NotBefore)
                        $HashTable.Add("ComputerCertificateHasPrivateKey", $False)
                        $HashTable.Add("SCVMMCertificateHasPrivateKey", $SCVMMCertificate.HasPrivateKey)
                        New-Object -TypeName PSCustomObject -Property $HashTable
                        Continue
                    }
                    
                    If ($SCVMMCertificate.FriendlyName -like 'SCVMM_CERTIFICATE_KEY_CONTAINER*') {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] Getting the computer certificate..."
                        Try {
                            $ComputerCertificates = Invoke-Command -ComputerName $($SCVMMCertificate.DNSNameList).Unicode -ScriptBlock $ScriptBlockComputerCertificates -ErrorAction Stop
                        }
                        Catch {
                            Write-Error -Exception $_.Exception -Message $_.Exception.Message
                            [HashTable] $HashTable = @{}
                            $HashTable.Add("Computer", $($SCVMMCertificate.DNSNameList).Unicode)
                            $HashTable.Add("SCVMMServer", $($env:COMPUTERNAME))
                            $HashTable.Add("IsCertificateMatched", $False)
                            $HashTable.Add("ComputerCertificateSerialNumber", $Null)
                            $HashTable.Add("SCVMMCertificateSerialNumber", $SCVMMCertificate.SerialNumber)
                            $HashTable.Add("ComputerCertificateSubjectName", $Null)
                            $HashTable.Add("SCVMMCertificateSubjectName", $SCVMMCertificate.SubjectName.Name)
                            $HashTable.Add("ComputerCertificateThumbprint", $Null)
                            $HashTable.Add("SCVMMCertificateThumbprint", $SCVMMCertificate.Thumbprint)
                            $HashTable.Add("ComputerCertificateNotAfter", $Null)
                            $HashTable.Add("SCVMMCertificateNotAfter", $SCVMMCertificate.NotAfter)
                            $HashTable.Add("ComputerCertificateNotBefore", $Null)
                            $HashTable.Add("SCVMMCertificateNotBefore", $SCVMMCertificate.NotBefore)
                            $HashTable.Add("ComputerCertificateHasPrivateKey", $False)
                            $HashTable.Add("SCVMMCertificateHasPrivateKey", $SCVMMCertificate.HasPrivateKey)
                            New-Object -TypeName PSCustomObject -Property $HashTable
                            Continue
                        }
                        
                        ForEach ($ComputerCertificate in $ComputerCertificates) {
                            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] Matching Computer certificate [$($ComputerCertificate.SerialNumber)] with SCVMM certificate [$($SCVMMCertificate.SerialNumber)]..."
                            
                            [HashTable] $HashTable = @{}
                            $HashTable.Add("Computer", $($SCVMMCertificate.DNSNameList).Unicode)
                            $HashTable.Add("SCVMMServer", $($env:COMPUTERNAME))
                            
                            If ($ComputerCertificate.SerialNumber -ne $SCVMMCertificate.SerialNumber) {
                                Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] Serial Number doesn't match!"
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] Computer Certificate Serial Number: [$($ComputerCertificate.SerialNumber)]"
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] VMM Server Certificate Serial Number: [$($SCVMMCertificate.SerialNumber)]"
                                $HashTable.Add("IsCertificateMatched", $False)
                            }
                            Else {
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVMMComputerCertificateStatus] Certificates matched."
                                $HashTable.Add("IsCertificateMatched", $True)
                            }
                            $HashTable.Add("ComputerCertificateSerialNumber", $ComputerCertificate.SerialNumber)
                            $HashTable.Add("SCVMMCertificateSerialNumber", $SCVMMCertificate.SerialNumber)
                            $HashTable.Add("ComputerCertificateSubjectName", $ComputerCertificate.SubjectName.Name)
                            $HashTable.Add("SCVMMCertificateSubjectName", $SCVMMCertificate.SubjectName.Name)
                            $HashTable.Add("ComputerCertificateThumbprint", $ComputerCertificate.Thumbprint)
                            $HashTable.Add("SCVMMCertificateThumbprint", $SCVMMCertificate.Thumbprint)
                            $HashTable.Add("ComputerCertificateNotAfter", $ComputerCertificate.NotAfter)
                            $HashTable.Add("SCVMMCertificateNotAfter", $SCVMMCertificate.NotAfter)
                            $HashTable.Add("ComputerCertificateNotBefore", $ComputerCertificate.NotBefore)
                            $HashTable.Add("SCVMMCertificateNotBefore", $SCVMMCertificate.NotBefore)
                            $HashTable.Add("ComputerCertificateHasPrivateKey", $ComputerCertificate.HasPrivateKey)
                            $HashTable.Add("SCVMMCertificateHasPrivateKey", $SCVMMCertificate.HasPrivateKey)
                            New-Object -TypeName PSCustomObject -Property $HashTable
                        }
                    }
                }
                Write-Progress -Activity "Getting Certificates.." -Status "Processing: $($($SCVMMCertificate.DnsNameList).Unicode) ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Certificate Information.." -Completed
            }
        }
        #endregion
	}

	Process {
        Try {
            <#
            Enable-WSManCredSSP -Role Client -DelegateComputer * -Force -ErrorAction Stop | Out-Null # Enable CredSSP Client on localhost (Console VM)
            Invoke-Command -ComputerName $VMMOwnerNode -ScriptBlock {Enable-WSManCredSSP -Role Client -DelegateComputer * -Force -ErrorAction Stop} | Out-Null # Enable CredSSP Client role on VMM Server
            #>
            Invoke-Command -ComputerName $VMMOwnerNode -ScriptBlock {Enable-WSManCredSSP -Role Server -Force -ErrorAction Stop} | Out-Null # Enable CredSSP Server role on VMM Server
            Invoke-Command -ComputerName $VMMOwnerNode -ScriptBlock $ScriptBlock -Authentication Credssp -Credential $PSCredential | 
                Select-Object * -ExcludeProperty $ExcludeProperties
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
	}

	End {
		[System.GC]::Collect()
	}
}

Function Get-CPSVirtualMachineSnapshot {
    [CmdletBinding()]
    Param (       
        [Parameter(
            Position = 0,
            Mandatory = $True,
            ParameterSetName = "ClusterType"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("MC","CC","EC")]
        [String] $ClusterType,

        [Parameter(
            Position = 1,
            Mandatory = $False,
            HelpMessage = "Specify maximum no. of threads. Default is 4 threads. Maximum is 8 threads:"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,8)]
        [Int16] $MaxThreads = 4
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
            Import-Module -Name FailoverClusters -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
		
        $ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")

        #region Script Block
        $ScriptBlock = {
            [CmdletBinding()]
            Param (       
                [Parameter(
                    Position = 0,
                    Mandatory = $True
                )]
                [ValidateNotNullOrEmpty()]
                [String] $VMHost
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
                    $VerbosePreference = $SaveVerbosePreference
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
                }

                $ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")
            }
		    
            Process {
                Try {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVirtualMachineSnapshot] Getting the checkpoints associated with a virtual machine or snapshot for host [$VMHost]..."
                    $VMSnapshots = Invoke-Command -ComputerName $VMHost -ScriptBlock {Get-VM | Get-VMSnapshot} | Select-Object * -ExcludeProperty $ExcludeProperties
                    Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSVirtualMachineSnapshot] Debug Info (Virtual Machine Snapshots): $($VMSnapshots | ConvertTo-Json -Compress)"
                    Write-Output -InputObject $VMSnapshots
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                }
            }

            End {
                [System.GC]::Collect()
            }
        }
        #endregion
	}

	Process {
        Try {
            #region Get-CPSVMMOwnerNode
            $VMMServer = Get-CPSVMMOwnerNode
            #endregion
        
            #region Get-SCVMHost
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVirtualMachineSnapshot] [Get-SCVMHost] Getting virtual machine hosts (in responding state) for cluster type [$ClusterType]..."
            $VMHosts = Get-SCVMHost -VMMServer $VMMServer | 
                                        Where-Object {$_.ComputerState -eq 'Responding'} | 
                                            Select-Object FullyQualifiedDomainName,HostCluster | 
                                                Where-Object {$_.HostCluster -like "*$ClusterType*"} | 
                                                    ForEach-Object {$_.FullyQualifiedDomainName}
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVirtualMachineSnapshot] Identified $($VMHosts.Count) virtual machine hosts."
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSVirtualMachineSnapshot] Debug Info (Virtual Machine Hosts): $($VMHosts | ConvertTo-Json)"
            #endregion
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        #region Get-VMSnapshot
        [Array]::Sort($VMHosts)
        If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
            Invoke-PSRunSpace -InputObject $VMHosts -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose -Debug
        }
        ElseIf ($PSBoundParameters['Verbose']) {
            Invoke-PSRunSpace -InputObject $VMHosts -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose
        }
        ElseIf ($PSBoundParameters['Debug']) {
            Invoke-PSRunSpace -InputObject $VMHosts -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Debug
        }
        Else {
           Invoke-PSRunSpace -InputObject $VMHosts -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance
        }
        #endregion
	}

	End {
		[System.GC]::Collect()
	}
}