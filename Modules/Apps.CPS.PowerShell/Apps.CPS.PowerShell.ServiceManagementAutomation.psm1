##################################################################
# Module Manifest Name: Apps.CPS.PowerShell.ServiceManagementAutomation.psm1
# Module Manifest Description: Holds SMA related functions
# Author: Srinath Sadda
#################################################################

<#
    .SYNOPSIS
        CPS Service Management Automation Module.
    .DESCRIPTION
        Holds Service Management Automation related functions.
    .EXAMPLE
        Import-Module -Name .\Apps.CPS.PowerShell.psd1
    .NOTES
        Module Name: Apps.CPS.PowerShell.ServiceManagementAutomation.psm1
        Module Description: Holds Service Management Automation related functions.
        Author: Srinath Sadda
    .LINK
#>

Function Get-CPSSmaComputerName {
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
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaComputerName] Importing module 'ActiveDirectory'..."
            $VerbosePreference_ = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            If ($Null -ne (Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
                $VerbosePreference = $VerbosePreference_
                Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSSmaComputerName] 'ActiveDirectory' module was not found! Adding feature..."
                $VerbosePreference = "SilentlyContinue"
                Add-WindowsFeature -Name RSAT-AD-PowerShell | Out-Null
                Import-Module -Name ActiveDirectory
            }
            $VerbosePreference = $VerbosePreference_
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
	}

	Process {
		Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaComputerName] Identifying Sma computers..."
            $SmaComputers = @(Get-ADComputer -Filter * | Where-Object { $_.Name -imatch "^(?<prefix>[\w][\w-.]+)-Sma-\d\d$" })
            $SmaComputerNames = $SmaComputers.DNSHostName | Sort-Object
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaComputerName] Found $($SmaComputerNames.Count) Sma computers."
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaComputerName] Selected $($SmaComputerNames | Select-Object -First 1)"
            Write-Output -InputObject $($SmaComputerNames | Get-Random)
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
	}

	End {
		[System.GC]::Collect()
	}
}

Function Get-CPSSMAVariableValue {
    [CmdletBinding()]
    Param (
        [String] $SMAComputerName,
        [String] $Name
    )
	
    Begin {
		If ($PSBoundParameters['Verbose']) {
			$VerbosePreference = "Continue"
		}
		If ($PSBoundParameters['Debug']) {
			$DebugPreference = "Continue"
			$ConfirmPreference = "None"
		}
        
        $Value = $Null
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSMAVariableValue] [SMA Computer Name: $SMAComputerName] [Variable Name: $Name]"
	}

	Process {
        Try {
            If (Get-Module -Name Microsoft.SystemCenter.ServiceManagementAutomation) {
                $Variable = Get-SmaVariable -WebServiceEndpoint "https://$SMAComputerName/" -Name $Name
                If (!$Variable) {
                    Write-Error -Exception System.ArgumentNullException -Message "Variable $Name not found!" -ErrorAction Stop
                }
                $Value = $Variable.Value
            }
            Else {
                $Value = Invoke-Command -ComputerName $SMAComputerName -ArgumentList $Name -ScriptBlock {
                    Try {
                        $SaveVerbosePreference = $VerbosePreference
                        $VerbosePreference = "SilentlyContinue"
                        Import-Module -Name Microsoft.SystemCenter.ServiceManagementAutomation -Verbose:$False
                        $VerbosePreference = $SaveVerbosePreference
                        $Variable = Get-SmaVariable -WebServiceEndpoint "https://$($env:COMPUTERNAME)/" -Name $args[0]
                        If (!$Variable) {
                            Write-Error -Exception System.ArgumentNullException -Message "Variable $Name not found!" -ErrorAction Stop
                        }
                        Write-Output -InputObject $Variable.Value
                    }
                    Catch {
                        Write-Error -Exception $_.Exception -Message $_.Exception.Message
                    }
                }
            }
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSMAVariableValue] [Variable Name: $Name] [Variable Value: $Value]"
        Write-Output -InputObject $Value
	}

	End {
		[System.GC]::Collect()
	}
}

Function Get-CPSSmaRunbookLog {
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True)]
        [String] $RunbookName,

        [Parameter(
            Position = 1,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Int] $NumberOfJobs = 1,

        [Parameter(
            Position = 2,
            Mandatory = $False,
            HelpMessage = "Specify path to a directory to save runbook logs."
        )]
        [ValidateNotNullOrEmpty()]
        [String] $WriteToFolderPath
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
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Importing modules..."
            $VerbosePreference_ = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            Import-Module -Name Microsoft.SystemCenter.ServiceManagementAutomation -ErrorAction Stop
            $VerbosePreference = $VerbosePreference_
            
            $SmaServer = Get-CPSSmaComputerName
            $WebServiceEndpoint = "https://$($SmaServer)"
        }
        Catch {
            Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] $($_.Exception.Message.Replace(':','!'))"
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        #region Initial Configuration Tasks
        Try {
            If ($PSBoundParameters['WriteToFolderPath']) {
                If (!(Test-Path -Path $WriteToFolderPath)) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Creating a directory [$WriteToFolderPath] to save runbook logs..."
                    New-Item -Path $WriteToFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] The directory is created successfully."
                }
                Else {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] The directory [$WriteToFolderPath] is verified successfully."
                }
            }
        }
        Catch {
            Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] $($_.Exception.Message.Replace(':','!'))"
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
        #endregion
    }

    Process {
        #region Runbook Information
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Getting runbook [$RunbookName] information..."
            $SmaRunbook = Get-SmaRunbook -WebServiceEndpoint $WebServiceEndpoint -Name $RunbookName -ErrorAction Stop
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Identified runbook [$RunbookName]."
        }
        Catch {
            Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] $($_.Exception.Message.Replace(':','!'))"
            Return
        }
        #endregion

        #region Runbook Logging Configuration Check
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] [Runbook Name: $RunbookName] [Runbook ID: $($SmaRunbook.RunbookID)] [Verbose: $($SmaRunbook.LogVerbose)] [Debug: $($SmaRunbook.LogDebug)] [Progress: $($SmaRunbook.LogProgress)]"
        If (($SmaRunbook.LogVerbose -ne $True) -or ($SmaRunbook.LogDebug -ne $True) -or ($SmaRunbook.LogProgress -ne $True)) {
            Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Either Verbose, Debug or Progress logging is set to false, this can have an affect on the richness of the data collected for this runbook!"
            Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] To enable more logging for this runbook run the following Cmdlet: [Set-SmaRunbookConfiguration -Name $RunbookName -WebServiceEndpoint $WebServiceEndpoint -LogDebug `$True -LogProgress `$True -LogVerbose `$True]"
        }
        #endregion

        #region Runbook Jobs
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Getting last $NumberOfJobs job(s) information for the runbook [$RunbookName]..."
            [Array] $SmaJobs = Get-SmaJob -WebServiceEndpoint $WebServiceEndpoint -RunbookId $SmaRunbook.RunbookID -ErrorAction Stop | Sort-Object StartTime -Descending | Select-Object -First $NumberOfJobs
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Identified $($SmaJobs.Count) jobs."
        }
        Catch {
            Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] $($_.Exception.Message.Replace(':','!'))"
            Return
        }
        #endregion

        $I = 0
        ForEach ($SmaJob in $SmaJobs) {
            $I++
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Processing job [$($SmaJob.JobId)] ($I of $($SmaJobs.Count))..."

            #region WriteToFolderPath
            If ($PSBoundParameters['WriteToFolderPath']) {
                Try {
                    $LogPath = Join-Path -Path $WriteToFolderPath -ChildPath "RunbookLogs\$RunbookName-$($SmaJob.JobId).log"
                    New-Item -Path $LogPath -ItemType File -Force -ErrorAction Stop | Out-Null
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                    Continue
                }
            }
            #endregion

            #region Runbook Job Stream Information
            Try {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Getting output from the job..."
                [Array] $SmaJobOutput = Get-SmaJobOutput -Id $SmaJob.JobId -Stream Any -WebServiceEndpoint $WebServiceEndpoint -ErrorAction Stop | ForEach-Object { $_ } | Sort-Object StreamTime
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Identified $($SmaJobOutput.Count) output streams."
                $J = 0
                ForEach ($Stream in $SmaJobOutput) {
                    $J++
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Processing output stream ($J of $($SmaJobOutput.Count))..."
                    Write-Output -InputObject $Stream
                    If ($PSBoundParameters['WriteToFolderPath']) {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] Writing output stream information to log file [$LogPath]..."
                        $Stream | Out-File -FilePath $LogPath -Append
                    }
                }
            }
            Catch {
                Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSSmaRunbookLog] $($_.Exception.Message.Replace(':','!'))"
                Continue
            }
            #endregion
        }
    }

    End {
        [System.GC]::Collect()
    }
}