##################################################################
# Module Manifest Name: Apps.CPS.PowerShell.HyperV.psm1
# Module Manifest Description: Holds Hyper-V related functions
# Author: Srinath Sadda
#################################################################

<#
    .SYNOPSIS
        CPS Hyper-V Module.
    .DESCRIPTION
        Holds Hyper-V related functions.
    .EXAMPLE
        Import-Module -Name .\Apps.CPS.PowerShell.psd1
    .NOTES
        Module Name: Apps.CPS.PowerShell.HyperV.psm1
        Module Description: Holds Hyper-V related functions.
        Author: Srinath Sadda
    .LINK
#>

Function Get-CPSHyperVClusterStatus {
    [CmdletBinding()]
    Param (       
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [String] $ClusterName,

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
            Import-Module -Name FailoverClusters -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        If (($ClusterName -eq "localhost") -or ($ClusterName -eq "127.0.0.1")) {
            $ClusterName = $env:COMPUTERNAME
        }
	}

	Process {
        #region Cluster
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSHyperVClusterStatus] [Get-Cluster] Getting cluster information for the given cluster name [$ClusterName]..."
            $Cluster = Get-Cluster -Name $ClusterName | Select-Object *
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSHyperVClusterStatus] Debug Info (Cluster): $($Cluster | ConvertTo-Json -Compress)"
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
        #endregion

        #region Cluster Nodes
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSHyperVClusterStatus] [Get-ClusterNode] Getting cluster nodes..."
            $ClusterNodes = Get-ClusterNode -Cluster $(Get-Cluster -Name $ClusterName) # Cluster Nodes
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSHyperVClusterStatus] Identified $($ClusterNodes.Count) cluster nodes."
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSHyperVClusterStatus] Debug Info (Cluster Nodes): $($ClusterNodes | ConvertTo-Json -Compress)"
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
        #endregion

        #region Active Cluster Nodes
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSHyperVClusterStatus] Identifying active cluster nodes..."
        $ActiveClusterNodes = ($ClusterNodes | Where-Object { $_.State -like "Up" })
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSHyperVClusterStatus] Identified $($ActiveClusterNodes.Count) active cluster nodes."
        Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSHyperVClusterStatus] Debug Info (Active Cluster Nodes): $($ActiveClusterNodes | ConvertTo-Json -Compress)"
        #endregion
	}

	End {
		[System.GC]::Collect()
	}
}