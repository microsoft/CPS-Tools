##################################################################
# Module Manifest Name: Apps.CPS.PowerShell.FailoverClusters.psm1
# Module Manifest Description: Holds Failover Clusters related functions
# Author: Srinath Sadda
#################################################################

<#
    .SYNOPSIS
        CPS Failover Clusters Module.
    .DESCRIPTION
        Holds Failover Clusters related functions.
    .EXAMPLE
        Import-Module -Name .\Apps.CPS.PowerShell.psd1
    .NOTES
        Module Name: Apps.CPS.PowerShell.FailoverClusters.psm1
        Module Description: Holds Failover Clusters related functions.
        Author: Srinath Sadda
    .LINK
#>

Function Get-CPSClusterHealthOverview {
    [CmdletBinding()]
    [OutputType([System.Object])]
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

        $Prefix = $env:COMPUTERNAME.Split('-')[0]

        Try {
            $SaveVerbosePreference = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            Import-Module -Name BitsTransfer -Verbose:$False
            Import-Module -Name PSWorkflow -Verbose:$False
            Import-Module -Name VirtualMachineManager -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
    }

    Process {
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterHealthOverview] [Get-SCStorageArray] Getting storage health..."
            $Clusters = Get-Cluster -Domain $env:USERDNSDOMAIN
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterHealthOverview] Identified $($Clusters.Count) clusters in domain $($env:USERDNSDOMAIN)."
            $I = 0
            ForEach ($Cluster in $Clusters) {
                $I++
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterHealthOverview] Processing cluster $($Cluster.Name) ($I of $($Clusters.Count))..."
                [Array] $ClusterNodes += Get-ClusterNode -Cluster $Cluster.Name | Select-Object Cluster,Name,State
                [Array] $ClusterNetworks += Get-ClusterNetwork -Cluster $Cluster.Name | Select-Object Cluster,Name,State
                [Array] $ClusterNetworkInterfaces += Get-ClusterNetworkInterface -Cluster $Cluster.Name | Select-Object Cluster,Network,Adapter,AdapterId,Name,State
                [Array] $ClusterGroups += ($Cluster | Where-Object {$_.Name -like "$Prefix-*"} | ForEach-Object {Get-ClusterGroup -Cluster $_.Name | Select-Object Cluster,Name,State})
                [Array] $ClusterResources += ($Cluster | Where-Object {$_.Name -like "$Prefix-*"} | ForEach-Object {Get-ClusterResource -Cluster $_.Name | Select-Object Cluster,OwnerNode,Name,State})
                [Array] $ClusterSharedVolumes += Get-ClusterSharedVolume -Cluster $Cluster.Name
            }

            $ClusterHealthOverview = New-Object -TypeName PSObject -Property @{
                ClusterNodes = $ClusterNodes
                ClusterNetworks = $ClusterNetworks
                ClusterNetworkInterfaces = $ClusterNetworkInterfaces
                ClusterGroups = $ClusterGroups
                ClusterResources = $ClusterResources
                ClusterSharedVolumes = $ClusterSharedVolumes
            }

            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSClusterHealthOverview] Debug Info (Cluster Health Overview): $($ClusterHealthOverview | ConvertTo-Json)"
            Write-Output -InputObject $ClusterHealthOverview
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
        }
    }

    End {
        [System.GC]::Collect()
    }
}