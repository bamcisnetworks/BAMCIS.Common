#region Test Functions

Function Get-RegistryKeyEntries {
	<#
		.SYNOPSIS
			Gets all of the properties and their values associated with a registry key.

		.DESCRIPTION
			The Get-RegistryKeyEntries cmdlet gets each entry and its value for a specified registry key.

		.PARAMETER Path
			The registry key path in the format that PowerShell can process, such as HKLM:\Software\Microsoft or Registry::HKEY_LOCAL_MACHINE\Software\Microsoft

		.INPUTS
			System.String

				You can pipe a registry path to Get-RegistryKeyEntries.

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]

		.EXAMPLE
			Get-RegistryEntries -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall

			Gets all of the entries associated with the registry key. It does not get any information about subkeys.

		.NOTES
			AUTHOR: Michael Haken	
			LAST UPDATE: 2/27/2016

		.FUNCTIONALITY
			The intended use of this cmdlet is to supplement the Get-ItemProperty cmdlet to get the values for every entry in a registry key.
	#>
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCustomObject[]])]
	Param(
		[Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
		[ValidateScript({
			Test-Path -Path $_
		})]
		[ValidateNotNullOrEmpty()]
		[System.String]$Path
	)

	Begin {}

	Process
	{
		Get-Item -Path $Path | Select-Object -ExpandProperty Property | ForEach-Object {
			Write-Output -InputObject ([PSCustomObject]@{"Path"=$Path;"Property"="$_";"Value"=(Get-ItemProperty -Path $Path -Name $_ | Select-Object -ExpandProperty $_)})
		}
	}

	End {}
}

Function Invoke-WhereNotMatchIn {
	<#
		.SYNOPSIS
			The cmdlet identifies items from an input that do not match a set of match terms. Essentially, this filters out items from the
			input against an array of filters.

		.DESCRIPTION
			The cmdlet takes an input array of objects. It compares each of these objects, or a property of the object against
			an array of match terms. If the item (or its property) does not match any of the match terms, it is returned to the pipeline.

		.PARAMETER InputObject
			An array of items that need to be filtered. The items can be primitive types, strings, or objects. If the items are complex objects, you should
			specify a property to be compared against the match terms.

		.PARAMETER Matches
			The set of string values to compare against the input items or a property of the input items. Any item in the Matches parameter that satifies
			the "-ilike" operator against the input item will cause that item to be filtered out of the results.

		.PARAMETER Property
			If the input items are complex objects, specify a property of those items to be compared against the Matches parameter.

		.EXAMPLE
			$Items = @("one", "oneTwo", "two", "oneThree", "three")
			$Results = Invoke-WhereNotMatchIn -Input $Items -Matches @("one*", "*two*")

			The results of this operation would be an array as follows: @("two", "three").

		.EXAMPLE
			$Items = @([PSCustomObject]@{Name = "One"; Value = "1"}, @{Name = "Two"; Value = "2"})
			$Results = Invoke-WhereNotMatchIn -Input $Items -Matches ("one") -Property "Name"
			
		.INPUTS
			System.Object[]

		.OUTPUTS
			System.Object[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATED: 10/24/2017

	#>
	[CmdletBinding()]
	[Alias("Where-NotMatchIn")]
	[OutputType([System.Object[]])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [System.Object[]]$InputObject,

        [Parameter(Position = 1)]
        [System.String[]]$Matches,

        [Parameter()]
        [System.String]$Property = [System.String]::Empty
    )

    Begin {
    }

    Process {
		

        foreach($Item in $InputObject) {
            $Match = $false

            if ($Property -eq [System.String]::Empty) {
                $Value = $Item
            }
            else {
                $Value = $Item.$Property
            }

            foreach ($Matcher in $Matches) {
				
                if ($Value -ilike $Matcher) {
                    $Match = $true
                    break
                }
            }

            if (!$Match) {
                Write-Output -InputObject $Item
            }
        }
    }

    End {       
    }
}

Function Test-RegistryKeyProperty {
	<#
		.SYNOPSIS
			Tests the existence of a registry value 

		.DESCRIPTION
			The Test-RegistryKeyProperty cmdlet test the extistence of a registry value (property of a key).

		.PARAMETER Key
			The registry key to test for containing the property.

		.PARAMETER PropertyName
			The property name to test for.

        .EXAMPLE
			Test-RegistryKeyProperty -Key "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing" -PropertyName PendingFileRenameOperations 
	        
			Returns true or false depending on the existence of the property

		.INPUTS
			None

		.OUTPUTS
			System.Boolean

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/28/2016
	#>
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	Param (
		[Parameter(Position = 0, Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Key,

		[Parameter(Position = 1, Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$PropertyName
	)

	Begin {
	}

	Process {
		Get-ItemProperty -Path $Key -Name $PropertyName -ErrorAction SilentlyContinue | Out-Null
		Write-Output -InputObject $?
	}

	End {
	}
}

Function Test-IsLocalAdmin {
	<#
		.SYNOPSIS
			Tests if the current user has local administrator privileges.

		.DESCRIPTION
			The Test-IsLocalAdmin cmdlet tests the user's current Windows Identity for inclusion in the BUILTIN\Administrators role.

		.INPUTS
			None

		.OUTPUTS
			System.Boolean

		.EXAMPLE
			Test-IsLocalAdmin

			This command returns true if the current user is running the session with local admin credentials and false if not.

		.NOTES
			AUTHOR: Michael Haken	
			LAST UPDATE: 2/27/2016

		.FUNCTIONALITY
			The intended use of this cmdlet is to test for administrative credentials before running other commands that require them.
	#>
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	Param()

	Begin {}

	Process {
		Write-Output -InputObject ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
	}

	End {}
 }

#endregion



#region Parallel / Using / Processing

Function Invoke-ForEachParallel {
	<#
		.SYNOPSIS
			Runs a script in a multi-threaded foreach.

		.DESCRIPTION
			The cmdlet runs through each input value and executes the script in a new thread.

		.PARAMETER ScriptBlock
			The script to execute on each input object.

		.PARAMETER InputObject
			The array of items to provide as input to the foreach.

		.PARAMETER Parameters
			A hashtable of additional parameters to provide to the script. For example @{Name = "MyService", Priority = 1} could be used by a scriptblock that looked like

			{
				Param(
					$Name,
					$Priority
				)

				Write-Host $Name
				Write-Host $Priority
			}

		.PARAMETER InputParamName
			If the input object needs to be associated with a parameter in the script, define its parameter name with this parameter. For example, consider the following Windows services:

			@("Winmgmt", "WinRM") | Invoke-ForEachParallel {
				Param(
					$Type
					$Name
				)
				Get-Service $Name
			} -InputParamName "Name"

			This will ensure that Winmgmt and WinRM are provided to the $Name parameter and not $Type

		.PARAMETER MinimumThreads
			The minimum number of threads to use, this defaults to 1.

		.PARAMETER MaximumThreads
			The maximum number of threads to use, this defaults to 4. This must be greater than or equal to the minimum threads.

		.PARAMETER WaitTime
			The amount of time, in milliseconds, the function waits in between checking the status of each task. For long running tasks
			you can increase this time to utilize less resources during execution.

        .EXAMPLE
			@("Winmgmt", "WinRM") | Invoke-ForEachParallel {
				Param(
					$Name
				)
				Get-Service $Name
			}

			This will return the service objects for the Winmgmt and WinRM services.

		.EXAMPLE
			$Results = Invoke-ForEachParallel -InputObject ("Hello", "Goodbye") -ScriptBlock {
				Param(
					$Greeting,
					$FirstName,
					$LastName
				)

				Write-Output -InputObject ($Greeting $FirstName $LastName)

			} -Parameters @{FirstName = "John", LastName = "Smith"}

			The example would execute two tasks, one outputing "Hello John Smith" and the other outputing "Goodbye John Smith", but not 
			necessarily in that order. The InputObject items are mapped against the parameter in the first position of the script, $Greeting, 
			while the additional parameters are mapped by matching their name.

		.INPUTS
			System.Object[]

		.OUTPUTS
			System.Object[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/26/2016
	#>
	[CmdletBinding()]
	[OutputType([System.Object[]])]
	[Alias("ForEach-ObjectParallel")]
	Param(	       
		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "ScriptBlock")]
		[ValidateNotNull()]
		[System.Management.Automation.ScriptBlock]$ScriptBlock,

		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Cmdlet")]
		[ValidateScript({
			Get-Command -Name $_
		})]
		[System.String]$Cmdlet,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
		[ValidateNotNull()]
		[System.Object[]]$InputObject,

		[Parameter()]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Parameters,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
        [System.String]$InputParamName = [System.String]::Empty,

		[Parameter()]
		[System.UInt32]$MinimumThreads = 1,

		[Parameter()]
		[ValidateScript({
            $_ -ge $MinimumThreads
		})]
		[System.UInt32]$MaximumThreads = 4,

        [Parameter()]
        [System.UInt32]$WaitTime = 100
	)

	Begin {
	}

	Process {
		$Jobs = New-Object -TypeName System.Collections.ArrayList
		$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
		$RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($MinimumThreads, $MaximumThreads, $SessionState, $Host)
		$RunspacePool.Open()

		foreach ($Item in $InputObject) {
			$Pipeline = [System.Management.Automation.PowerShell]::Create()

			if ($PSCmdlet.ParameterSetName -eq "ScriptBlock")
			{
				$Pipeline.AddScript($ScriptBlock) | Out-Null
			}
			elseif ($PSCmdlet.ParameterSetName -eq "Cmdlet")
			{
				$Pipeline.AddCommand($Cmdlet) | Out-Null
			}
			else
			{
				throw (New-Object -TypeName System.ArgumentException("The parameter set name could not be determined from the given parameters."))
			}

			if ($Parameters.Length -gt 0)
			{
				$Pipeline.AddParameters($Parameters) | Out-Null
			}

            if (![System.String]::IsNullOrEmpty($InputParamName))
            {
                $Pipeline.AddParameter($InputParamName, $Item) | Out-Null
            }
            else
            {
                $Pipeline.AddArgument($Item) | Out-Null
            }

			$Pipeline.RunspacePool = $RunspacePool
			$AsyncHandle = $Pipeline.BeginInvoke()

			$Jobs.Add(@{Handle = $AsyncHandle; Pipeline = $Pipeline}) | Out-Null
		}

		$Results = @()
        $TotalJobs = $Jobs.Count

		while ($Jobs.Count -gt 0)
		{
			Write-Progress -Activity "Waiting for async tasks" `
						-PercentComplete ((($TotalJobs - $Jobs.Count) / $TotalJobs) * 100) `
						-Status ( ($TotalJobs - $Jobs.Count).ToString() + " of $TotalJobs completed, $($Jobs.Count) remaining")

			foreach($Job in ($Jobs | Where-Object {$_.Handle.IsCompleted -eq $true}))
			{
				$Results += $Job.Pipeline.EndInvoke($Job.Handle)
				$Job.Pipeline.Dispose() | Out-Null
                $Jobs.Remove($Job)
			}

			Start-Sleep -Milliseconds $WaitTime
		}

		Write-Progress -Activity "Waiting for async tasks" -Completed

		$RunspacePool.Close() | Out-Null
		$RunspacePool.Dispose() | Out-Null

		Write-Output -InputObject $Results
	}

	End {
	}
}

Function Invoke-CommandInNewRunspace {
	<#
		.SYNOPSIS
			Runs a scriptblock in a new powershell runspace.

		.DESCRIPTION
			The Invoke-CommandInNewRunspace cmdlet uses a clean PowerShell runspace to execute the provided script block.

		.PARAMETER ScriptBlock
			The script to execute on each input object.

		.PARAMETER Parameters
			A hashtable of additional parameters to provide to the script. For example @{Name = "MyService", Priority = 1} could be used by a scriptblock that looked like

			{
				Param(
					$Name,
					$Priority
				)

				Write-Host $Name
				Write-Host $Priority
			}

        .EXAMPLE
			Invoke-CommandInNewRunspace -ScriptBlock {Get-Service}
	        
			Invokes the Get-Service cmdlet in a new runspace.

		.EXAMPLE
			Invoke-CommandInNewRunspace -ScriptBlock {
				Param(
					$Name
				)	
			
				Get-Process $Name
			} -Parameters @{Name = "winlogon"}

			Performs a Get-Process for the winlogon process in a new runspace

		.INPUTS
			None

		.OUTPUTS
			System.Object

			This depends on what is returned from the ScriptBlock

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/26/2016
	#>
	[CmdletBinding()]
	[OutputType([System.Object])]
	Param(
		
		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "ScriptBlock")]
		[ValidateNotNull()]
		[System.Management.Automation.ScriptBlock]$ScriptBlock,

		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Cmdlet")]
		[ValidateScript({
			Get-Command -Name $_
		})]
		[System.String]$Cmdlet,

		[Parameter(Position = 1)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Parameters
	)

	Begin {
	}

	Process {
		$Results = $null
		$Runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()

		#Create a new PowerShell instance
		$Pipeline = [System.Management.Automation.PowerShell]::Create()

		try {
			#Assign the PowerShell instance to the new RunspacePool we created
			$Pipeline.Runspace = $Runspace

			#Open the runspace
			$Runspace.Open()

			#If the cmdlet was run using a script block, add it
			if ($PSCmdlet.ParameterSetName -eq "ScriptBlock")
			{
				$Pipeline.AddScript($ScriptBlock) | Out-Null
			}
			elseif ($PSCmdlet.ParameterSetName -eq "Cmdlet")
			{
				$Pipeline.AddCommand($Cmdlet) | Out-Null
			}
			else
			{
				throw New-Object -TypeName System.ArgumentException("The parameter set name could not be determined from the given parameters.")
			}

			#Add parameters if they are defined
			if ($Parameters.Length -gt 0)
			{
				$Pipeline.AddParameters($Parameters) | Out-Null
			}

			#Invoke the command synchronously
			$Results = $Pipeline.Invoke()
		}
		finally {
			#Dispose the powershell instance
			$Pipeline.Dispose() | Out-Null
		
			#Terminate the runspace
			$Runspace.Close() | Out-Null
			$Runspace.Dispose() | Out-Null
		}

		Write-Output -InputObject $Results
	}

	End {
		
	}
}

Function Start-ProcessWait {
	<#
		.SYNOPSIS
			Starts a new process and waits for it to complete.

		.DESCRIPTION
			This cmdlet starts a new process using .NET System.Diagnostics.Process and waits for it to complete. It optionally writes the standard out of the process to the log file.

		.PARAMETER FilePath
			The path to the executable, script, msi, msu, etc to be executed.

		.PARAMETER ArgumentList
			An array of arguments to run with the file being executed. This defaults to an empty array.

		.PARAMTER EnableLogging
			Specify to write standard output or standard errors to the log file.

		.INPUTS
			None

		.OUTPUTS
			None

        .EXAMPLE
			Start-ProcessWait -FilePath "c:\installer.msi" -EnableLogging -ArgumentList @("/qn")

			Launches a quiet installation from installer.msi with a no restart option. Logging is also enabled.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 8/24/2016
	#>
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateScript({
			Test-Path -Path $_	
		})]
		[System.String]$FilePath,

		[Parameter()]
		[ValidateNotNull()]
		[System.String[]]$ArgumentList = @(),

		[Parameter()]
		[Switch]$EnableLogging
	)

	Begin {
	}

	Process {
		if (Test-Path -Path $FilePath) {
			[System.IO.FileInfo]$FileInfo = New-Object -TypeName System.IO.FileInfo($FilePath)

			[System.Diagnostics.Process]$Process = New-Object -TypeName System.Diagnostics.Process
			$Process.StartInfo.RedirectStandardOutput = $true
			$Process.StartInfo.UseShellExecute = $false
			$Process.StartInfo.CreateNoWindow = $true
			$Process.StartInfo.RedirectStandardError = $true

            switch($FileInfo.Extension.ToUpper()) {
                ".MSU" {
					$ArgumentList += "$FilePath"
					$Process.StartInfo.Filename = "$env:SystemRoot\System32\WUSA.EXE"
					$Process.StartInfo.Arguments = ($ArgumentList -join " ")
					break
                }
                ".MSP" {
                    $ArgumentList += "$FilePath"
					$ArgumentList += "/update"
					$Process.StartInfo.Filename = "MSIEXEC.EXE"
					$Process.StartInfo.Arguments = ($ArgumentList -join " ")
					break
                }
				".MSI" {
                    $ArgumentList += "$FilePath"
					$Process.StartInfo.Filename = "MSIEXEC.EXE"
					$Process.StartInfo.Arguments = ($ArgumentList -join " ")
					break
                }
                default {
					$Process.StartInfo.Filename = "$FilePath"
					$Process.StartInfo.Arguments = ($ArgumentList -join " ")
					break
                }
            }

            Write-Log -Message "Executing $FilePath $($ArgumentList -Join " ")" -Level VERBOSE

			$Process.Start() | Out-Null
			
			if ($EnableLogging) {
				while (!$Process.HasExited) {
					 while (![System.String]::IsNullOrEmpty(($Line = $Process.StandardOutput.ReadLine()))) {
						Write-Log -Message $Line -NoInfo
					}

					Start-Sleep -Milliseconds 100
				}

				if ($Process.ExitCode -ne 0) {
					$Line = $Process.StandardError.ReadToEnd()
					if (![System.String]::IsNullOrEmpty($Line)) {
						Write-Log -Message $Line -Level ERROR -NoInfo
					}
				}
				else {
					$Line = $Process.StandardOutput.ReadToEnd()
					if (![System.String]::IsNullOrEmpty($Line)) {
						Write-Log -Message $Line -NoInfo
					}
				}
			}
			else {
				$Process.WaitForExit()
			}
        }
        else {
            Write-Log -Message "$FilePath not found." -Level WARNING
        }
	}

	End {}
}

Function Invoke-Using {
    <#
        .SYNOPSIS
            Provides a C#-like using() block to automatically handle disposing IDisposable objects.

        .DESCRIPTION
            The cmdlet takes an InputObject that should be an IDisposable, executes the ScriptBlock, then disposes the object.

        .PARAMETER InputObject
            The object that needs to be disposed of after running the scriptblock.

        .PARAMETER ScriptBlock
            The scriptblock to execute with the "using" variable.

        .EXAMPLE
            Invoke-Using ([System.IO.StreamWriter]$Writer = New-Object -TypeName System.IO.StreamWriter([System.Console]::OpenStandardOutput())) {
                $Writer.AutoFlush = $true
                [System.Console]::SetOut($Writer)
                $Writer.Write("This is a test.")
            }

            The StreamWriter is automatically disposed of after the script block is executed. Future calls to $Writer would fail. Please notice
            that the open "{" bracket needs to be on the same line as the cmdlet.

        .INPUTS
            System.Management.Automation.ScriptBlock

        .OUTPUTS
            None

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 6/21/2017

    #>
	[Alias("Using")]
    [CmdletBinding()]
	[OutputType()]
    Param(
        [Parameter(Mandatory = $true)]
		[ValidateNotNull()]
		[ValidateScript({
			$_ -is [System.IDisposable]
		})]
        [System.Object]$InputObject,
 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[ValidateNotNull()]
        [System.Management.Automation.ScriptBlock]$ScriptBlock
    )
    
    Begin {
    }
    
    Process 
    {       
        try
        {
            & $ScriptBlock
        }
        finally
        {
            if ($InputObject -ne $null)
            {
				$InputObject.Dispose()
            }
        }
    }

    End {
    }
}

#endregion



#region Converters

Function ConvertFrom-Xml {
	<#
		.SYNOPSIS
			Converts an Xml object to a PSObject.

		.DESCRIPTION
			The ConvertFrom-Xml recursively goes through an Xml object and enumerates the properties of each inputted element. Those properties are accessed and added to the returned object.

			An XmlElement that has attributes and XmlText will end up with the XmlText value represented as a "#name" property in the resulting object.

		.EXAMPLE
			ConvertFrom-Xml -InputObject $XmlObj

			Returns an PSObject constructed from the $XmlObj variable

		.PARAMETER InputObject
			The InputObject is an Xml type in the System.Xml namespace. It could be an XmlDocument, XmlElement, or XmlNode for example. It cannot be a collection of Xml objects.

		.INPUTS
			System.Xml

		.OUTPUTS
			System.Management.Automation.PSObject

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 3/31/2015
	#>
    [CmdletBinding()]
	[OutputType([System.Management.Automation.PSObject])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [ValidateScript({
			$_.GetType().Namespace -eq "System.Xml"
		})]
        $InputObject
    )

    Begin {       
    }

    Process {
		$private:Hash = @{}
        
        Get-Member -InputObject $InputObject -MemberType Property | Where-Object {$_.Name -ne "xml" -and (![System.String]::IsNullOrEmpty($_.Name))} | ForEach-Object {
            $PropertyName = $_.Name
            $InputItem = $InputObject.($PropertyName)

            #There are multiple items with the same tag name
            if ($InputItem.GetType() -eq [System.Object[]]) {
                
                #Make the tag name an array
                $private:Hash.($PropertyName) = @()

                #Go through each item in the array
                $InputItem | Where-Object {$_ -ne $null} | ForEach-Object {
                    
                    #Item is an object in the array
                    $Item = $_
                    [System.Type]$Type = $Item.GetType()

                    if ($Type.IsPrimitive -or $Type -eq [System.String]) {                   
                        $private:Hash.($PropertyName) = $Item
                    }
                    else {
						#Create a temp variable to hold the new object that will be added to the array
						$Temp = @{}  
                                
						#Make attributes properties of the object 
						$Item.Attributes | ForEach-Object {
							$Temp.($_.Name) = $_.Value
						}

						#As an XmlElement, the element will have at least 1 childnode, it's value
						$Item.ChildNodes | Where-Object {$_ -ne $null -and ![System.String]::IsNullOrEmpty($_.Name)} | ForEach-Object {
							$ChildNode = $_
   
							if ($ChildNode.HasChildNodes) {
								#If the item has 1 childnode and the childnode is XmlText, then the child is this type of element,
								#<Name>ValueText</Name>, so its child is just the value
								if ($ChildNode.ChildNodes.Count -eq 1 -and $ChildNode.ChildNodes[0].GetType() -eq [System.Xml.XmlText] -and !($ChildNode.HasAttributes)) {
									$Temp.($ChildNode.ToString()) = $ChildNode.ChildNodes[0].Value
								}
								else {
									$Temp.($ChildNode.ToString()) = ConvertFrom-Xml -InputObject $ChildNode
								}
							}
							else {
								$Temp.($ChildNode.ToString()) = $ChildNode.Value
							}
						}
					
						$private:Hash.($PropertyName) += $Temp
					}
                }
            }
            else {
                if ($InputItem -ne $null) {
                    $Item = $InputItem
                    [System.Type]$Type = $InputItem.GetType()
                    
                    if ($Type.IsPrimitive -or $Type -eq [System.String]) {                   
                        $private:Hash.($PropertyName) = $Item
                    }
                    else {

                        $private:Hash.($PropertyName) = @{}  
                                
                        $Item.Attributes | ForEach-Object {
                            $private:Hash.($PropertyName).($_.Name) = $_.Value
                        }

                        $Item.ChildNodes | Where-Object {$_ -ne $null -and ![System.String]::IsNullOrEmpty($_.Name)} | ForEach-Object {
                            $ChildNode = $_
                            
                            if ($ChildNode.HasChildNodes) {
                                if ($ChildNode.ChildNodes.Count -eq 1 -and $ChildNode.ChildNodes[0].GetType() -eq [System.Xml.XmlText] -and !($ChildNode.HasAttributes)) {      
                                    $private:Hash.($PropertyName).($ChildNode.ToString()) = $ChildNode.ChildNodes[0].Value
                                }
                                else {
                                    $private:Hash.($PropertyName).($ChildNode.ToString()) = ConvertFrom-Xml -InputObject $ChildNode
                                }
                            }
                            else {
                                $private:Hash.($PropertyName).($ChildNode.ToString()) = $ChildNode.Value
                            }
                        }
                    }
                }
            }                  
        }

		 Write-Output -InputObject (New-Object -TypeName System.Management.Automation.PSObject -Property $private:Hash)
    }

    End {      
    }
}

Function ConvertTo-HtmlTable {
	<#
		.SYNOPSIS
			Converts an object to an HTML table.

		.DESCRIPTION
			The ConvertTo-HtmlTable cmdlet takes an input object and converts it to an HTML document containing a table. The html
			document is either written out to stdout or written to file if a destination is specified.

		.EXAMPLE
			ConvertTo-HtmlTable -CsvPath c:\test.csv -Title "Test Import File" -Destination c:\test.html

			Converts the csv file to an html file and saves the html to the specified destination.

		.PARAMETER CsvPath
			The path to the CSV file that will be converted to HTML. Currently, this is the only supported input format.

		.PARAMETER Title
			An optional title to display on the HTML.

		.PARAMETER Destination
			An optional parameter to save the HTML content to a file. If this parameter is not specified or is Null or Empty, the HTML will be written to the pipeline.

		.PARAMETER IgnoreHeaders
			An array of any headers in the CSV file to ignore when creating the HTML table. Data in these columns will not be added to the table.

		.INPUTS
			None

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/15/2017
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName= "Csv", Position = 0)]
		[ValidateScript({Test-Path -Path $_})]
        [System.String]$CsvPath,

        [Parameter()]
		[ValidateNotNullOrEmpty()]
        [System.String]$Title = [System.String]::Empty,

        [Parameter(Position = 1)]
		[ValidateNotNullOrEmpty()]
        [System.String]$Destination = [System.String]::Empty,

        [Parameter(ParameterSetName="Csv")]
		[ValidateNotNull()]
        [System.String[]]$IgnoreHeaders = @()
    )

    Begin {
    }

    Process {
		switch ($PSCmdlet.ParameterSetName) {
            "Csv" {
                $Data = Import-Csv -Path $CsvPath
				if ($Data.Count -gt 0) {
					$Headers = Get-Member -InputObject $Data[0] -MemberType NoteProperty | Select-Object -ExpandProperty Name | Where-Object {$_.ToString().ToLower() -notin $IgnoreHeaders.ToLower()}
				}
				else {
					$Headers = @()
					Write-Log -Message "No content in the CSV." -Level VERBOSE
				}
            }
            default {
                throw "Could not determine parameter set."
            }
        }

        $Html = @"
<!DOCTYPE html>
<html>
	<head>
		<meta name="viewport" content="width=device-width" />
		<title>$Title</title>
	</head>
    <style>
        .logtable {
            width:100%;
            table-layout:fixed;
            border:1px solid black;
        }
        
        .logtable td {
            word-break:break-all;
            word-wrap:break-word;
            vertical-align:top;
			text-align:left;
        }

        .logtable th {
            text-align:center;
        }
    </style>
	<body style=`"width:1200px;margin-left:auto;margin-right:auto;`">
        <H1 style=`"text-align:center;`">$Title</H1>
        <div>
			 <table class=`"logtable`">
				<thead>

"@

		foreach ($Header in $Headers) {
			$Html += "<th>$Header</th>"
		}

		$Html += "</thead><tbody>"

		foreach ($Obj in $Data) {
			$Html += "<tr>"

			$Props = Get-Member -InputObject $Obj -MemberType NoteProperty | Select-Object -ExpandProperty Name | Where-Object {$_.ToString().ToLower() -notin $IgnoreHeaders.ToLower()}

			foreach ($Prop in $Props) {
				$Html += "<td>" + $Obj.$Prop + "</td>"
			}

			$Html += "</tr>"
		}

		$Html += "</tbody></table></div></body></html>"

		if (![System.String]::IsNullOrEmpty($Destination)) {
			Set-Content -Path $Destination -Value $Html -Force
		}
		else {
			Write-Output -InputObject $Html
		}
    }

    End {
    }
}

Function Merge-Hashtables {
	<#
		.SYNOPSIS 
			Merges two hashtables.

		.DESCRIPTION
			The cmdlet merges a second hashtable with a source one. The second hashtable will add or overwrite its values to a copy of the first. Neither of the two input hashtables are modified.

		.PARAMETER Source
			The source hashtable that will be added to or overwritten. The original hashtable is not modified.

		.PARAMETER Update
			The hashtable that will be merged into the source. This hashtable is not modified.

		.EXAMPLE
			Merge-Hashtables -Source @{"Key" = "Test"} -Data @{"Key" = "Test2"; "Key2" = "Test3"}

			This cmdlet results in a hashtable that looks like as follows: @{"Key" = "Test2"; "Key2" = "Test3"}

		.INPUTS
            None

        .OUTPUTS
            System.Collections.Hashtable

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/21/2017	
	#>

	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Source,

		[Parameter(Mandatory = $true)]
		[ValidateNotNull()]
		[System.Collections.Hashtable]$Update
	)

	Begin {
	}

	Process {
		# Make a copy of the source so it is not modified
		[System.Collections.Hashtable]$Output = $Source.Clone()

		# Check each key in the update to see if the output already has it
		foreach ($Key in $Update.Keys)
		{
			# If it does, update the value
			if ($Output.ContainsKey($Key))
			{
				$Output[$Key] = $Update[$Key]
			}
			else 
			{
				# If not, add the key/value
				$Output.Add($Key, $Update[$Key])
			}
		}

		Write-Output -InputObject $Output
	}

	End {
	}
}

Function ConvertTo-Hashtable {
	<#
		.SYNOPSIS 
			Converts a PSCustomObject to a Hashtable.

		.DESCRIPTION
			The cmdlet takes a PSCustomObject and converts all of its property key/values to a Hashtable. You can specify keys from the PSCustomObject to exclude or specify that empty values not be added to the Hashtable.

		.PARAMETER InputObject
			The PSCustomObject to convert.

		.PARAMETER Exclude
			The key values from the PSCustomObject not to include in the Hashtable.

		.PARAMETER NoEmpty
			Specify to not include keys with empty or null values from the PSCustomObject in the Hashtable.

		.EXAMPLE
			ConvertTo-Hashtable -InputObject ([PSCustomObject]@{"Name" = "Smith"})

			Converts the inputted PSCustomObject to a hashtable.

		.EXAMPLE 
			ConvertTo-Hashtable -InputObject ([PSCustomObject]@{"LastName" = "Smith", "Middle" = "", "FirstName" = "John"}) -NoEmpty -Exclude @("FirstName")

			Converts the inputted PSCustomObject to a hashtable. The empty property, Middle is excluded, and the property FirstName is excluded explicitly. This results
			in a hashtable @{"LastName" = "Smith"}

		.INPUTS
            System.Management.Automation.PSCustomObject

        .OUTPUTS
            System.Collections.Hashtable

        .NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 8/21/2017	
	#>
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[ValidateNotNull()]
		[PSCustomObject]$InputObject,

		[Parameter()]
		[ValidateNotNull()]
		[System.String[]]$Exclude = @(),

		[Parameter()]
		[Switch]$NoEmpty
	)

	Begin {
	}
	
	Process {
		[System.Collections.Hashtable]$Result = @{}

		$InputObject | Get-Member -MemberType "*Property" | Select-Object -ExpandProperty Name | ForEach-Object {
			if ($Exclude -inotcontains $_) {
				if ($NoEmpty -and -not ($InputObject.$_ -eq $null -or $InputObject.$_ -eq ""))
				{
					Write-Log -Message "Property $_ has an empty/null value." -Level VERBOSE
				}
				else 
				{
					$Result.Add($_, $InputObject.$_)
				}
			}
			else {
				Write-Log -Message "Property $_ excluded." -Level VERBOSE
			}
		}

		Write-Output -InputObject $Result
	}

	End {
	}
}

Function Convert-SecureStringToString {
	<#
		.SYNOPSIS
			The cmdlet converts a secure string to standard string.

		.DESCRIPTION
			The cmdlet converts a secure string to standard string.

		.PARAMETER SecureString
			The secure string to convert to a standard string

        .PARAMETER Encoding
             Defines the encoding that is used to produce the output string. This defaults to Unicode.

		.INPUTS
			System.Security.SecureString
		
		.OUTPUTS
			System.String

		.EXAMPLE 
			Convert-SecureStringToString -SecureString (ConvertTo-SecureString -String "test" -AsPlainText -Force)

			Converts the secure string created from the text "test" back to plain text.

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/25/2018
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [System.Security.SecureString]$SecureString,

		[Parameter()]
		[ValidateNotNull()]
		[System.Text.Encoding]$Encoding = [System.Text.Encoding]::Unicode
    )

    Begin {}

    Process { 
        [System.String]$PlainText = [System.String]::Empty
        [System.IntPtr]$IntPtr = [System.IntPtr]::Zero

        try 
        {     
            $IntPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)     
			$PlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($IntPtr)  
            [System.Byte[]]$Bytes = [System.Text.Encoding]::Unicode.GetBytes($PlainText)

            $PlainText = $Encoding.GetString($Bytes)

            Write-Output -InputObject $PlainText
        }   
        finally 
        {     
            if ($IntPtr -ne $null -and $IntPtr -ne [System.IntPtr]::Zero) 
			{       
				[System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($IntPtr)     
            }   
        }
    }

    End {      
    }
}

Function ConvertFrom-UnixTimestamp {
	<#
		.SYNOPSIS
			Converts a Unix timestamp to a DateTime object.
		
		.DESCRIPTION
			The cmdlet converts a unix timestamp to a DateTime object. The timestamp can be in milliseconds or seconds.
		
		.PARAMETER Timestamp
			The unix timestamp. This can be in seconds or milliseconds, the cmdlet defaults to interpreting this as milliseconds.

		.PARAMETER TimestampInSeconds
			Specifies that the timestamp should be interpreted in seconds.

		.EXAMPLE
			ConvertFrom-UnixTimestamp 1509494400000

			Converts the timestamp 1509494400000 to a DateTime which is Wednesday, November 1, 2017 12:00:00 AM.

		.INPUTS
			System.UInt64

		.OUTPUTS
			System.DateTime

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/14/2017
	#>
	[CmdletBinding()]
	[OutputType([System.DateTime])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[System.UInt64]$Timestamp,

		[Parameter()]
		[Switch]$TimestampInSeconds
	)

	Begin {
	}

	Process {

		[System.DateTime]$Epoch = New-Object -TypeName System.DateTime(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)

		if ($TimestampInSeconds)
		{
			Write-Output -InputObject ($Epoch.AddSeconds($Timestamp))
		}
		else
		{
			Write-Output -InputObject ($Epoch.AddMilliseconds($Timestamp))
		}
	}

	End {
	}
}

Function ConvertTo-UnixTimestamp {
	<#
		.SYNOPSIS
			Converts a DateTime object to a Unix timestamp.
		
		.DESCRIPTION
			The cmdlet converts a DateTime object to a unix timestamp in milliseconds or seconds past the epoch. It defaults to milliseconds.
		
		.PARAMETER Timestamp
			The DateTime object to convert. It will be converted to UTC and then translated.

		.PARAMETER OutputSeconds
			Specifies that output should be in seconds past the epoch instead of milliseconds

		.EXAMPLE
			ConvertTo-UnixTimestamp ([System.DateTime]::UtcNow)

			Converts the current time to a unix timestamp in milliseconds.

		.INPUTS
			System.DateTime

		.OUTPUTS
			System.UInt64

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/14/2017
	#>
	[CmdletBinding()]
	[OutputType([System.DateTime])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[System.DateTime]$Timestamp,

		[Parameter()]
		[Switch]$OutputSeconds
	)

	Begin {
	}

	Process {

		[System.DateTime]$Epoch = New-Object -TypeName System.DateTime(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)

		if ($OutputSeconds)
		{
			Write-Output -InputObject ([System.UInt64][System.Math]::Round(($Timestamp - $Epoch).TotalSeconds))
		}
		else
		{
			Write-Output -InputObject ([System.UInt64][System.Math]::Round(($Timestamp - $Epoch).TotalMilliseconds))
		}
	}

	End {
	}
}

#endregion


#region Dynamic Code

Function Import-Assembly {
	<#
		.SYNOPSIS
			Loads an assembly into the current session.

		.DESCRIPTION
			This cmdlet loads an assembly with the provided name if it is not already loaded.

		.PARAMETER AssemblyName
			The name of the assembly to load.

		.EXAMPLE
			Import-Assembly -AssemblyName System.Security

			Imports System.Security to the current PowerShell session.

		.INPUTS
			System.String

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken	
			LAST UPDATE: 1/25/2018
	#>
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$AssemblyName
	)

	Begin {

	}

	Process {
        $Names = [System.AppDomain]::CurrentDomain.GetAssemblies() | Select-Object -Property @{"Name" = "Name"; "Expression" = { $_.FullName.Split(",")[0] }} | Select-Object -ExpandProperty Name

        if ($Names -inotcontains $AssemblyName)
        {
            Write-Verbose -Message "Loading assembly $AssemblyName."
            [System.Reflection.Assembly]::LoadWithPartialName($AssemblyName) | Out-Null
        }
        else
        {
            Write-Verbose -Message "Assembly $AssemblyName is already loaded."
        }
	}

	End {
	}
}

#endregion

$script:UnboundExtensionMethod = @"
using System;
using System.Collections;
using System.Management.Automation;
using System.Reflection;

namespace BAMCIS.PowerShell.Common
{
    public static class ExtensionMethods 
    {
        private static readonly BindingFlags Flags = BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public;

        public static T GetUnboundParameterValue<T>(this PSCmdlet cmdlet, string paramName, int unnamedPosition = -1)
        {
            if (cmdlet != null)
            {
                // If paramName isn't found, value at unnamedPosition will be returned instead
                object Context = GetPropertyValue(cmdlet, "Context");
                object Processor = GetPropertyValue(Context, "CurrentCommandProcessor");
                object ParameterBinder = GetPropertyValue(Processor, "CmdletParameterBinderController");
                IEnumerable Args = GetPropertyValue(ParameterBinder, "UnboundArguments") as System.Collections.IEnumerable;

                if (Args != null)
                {
                    bool IsSwitch = typeof(SwitchParameter) == typeof(T);
                    string CurrentParameterName = String.Empty;
                    int i = 0;

                    foreach (object Arg in Args)
                    {

                        //Is the unbound argument associated with a parameter name
                        object IsParameterName = GetPropertyValue(Arg, "ParameterNameSpecified");

                        //The parameter name for the argument was specified
                        if (IsParameterName != null && true.Equals(IsParameterName))
                        {
                            string ParameterName = GetPropertyValue(Arg, "ParameterName") as string;
                            CurrentParameterName = ParameterName;

                            //If it's a switch parameter, there won't be a value following it, so just return a present switch
                            if (IsSwitch && String.Equals(CurrentParameterName, paramName, StringComparison.OrdinalIgnoreCase))
                            {
                                return (T)(object)new SwitchParameter(true);
                            }

                            //Since we have a current parameter name, the next value in Args should be the value supplied
                            //to the argument, so we can head on to the next iteration, this skips the remaining code below
                            //and starts the next item in the foreach loop
                            continue;
                        }

                        //We assume the previous iteration identified a parameter name, so this must be its
                        //value
                        object ParameterValue = GetPropertyValue(Arg, "ArgumentValue");

                        //If the value we have grabbed had a parameter name specified,
                        //let's check to see if it's the desired parameter
                        if (CurrentParameterName != String.Empty)
                        {
                            //If the parameter name currently being assessed is equal to the provided param
                            //name, then return the value of the param
                            if (CurrentParameterName.Equals(paramName, StringComparison.OrdinalIgnoreCase))
                            {
                                return ConvertParameter<T>(ParameterValue);
                            }
                            else
                            {
                                //Since this wasn't the parameter name we were looking for, clear it out
                                CurrentParameterName = String.Empty;
                            }
                        }
                        //Otherwise there wasn't a parameter name, so the argument must have been supplied positionally,
                        //check if the current index is the position whose value we want
                        //Since positional parameters have to be specified first, this will be evaluated and increment until
                        //we run out of parameters or find a parameter with a name/value
                        else if (i++ == unnamedPosition)
                        {
                            //Just return the parameter value if the position matches what was specified
                            return ConvertParameter<T>(ParameterValue);
                        }
                    }
                }

                return default(T);
            }
            else
            {
                throw new ArgumentNullException("cmdlet", "The PSCmdlet cannot be null.");
            }
        }

        private static object GetPropertyValue(object instance, string fieldName)
        {
            // any access of a null object returns null. 
            if (instance == null || String.IsNullOrEmpty(fieldName))
            {
                return null;
            }

            try
            {
                PropertyInfo PropInfo = instance.GetType().GetProperty(fieldName, Flags);
            
                if (PropInfo != null)
                {
                    try
                    {
                        return PropInfo.GetValue(instance, null);
                    }
                    catch (Exception) { }
                }

                // maybe it's a field
                FieldInfo FInfo = instance.GetType().GetField(fieldName, Flags);

                if (FInfo != null)
                {
                    try
                    {
                        return FInfo.GetValue(instance);
                    }
                    catch { }
                }
            }
            catch (Exception) { }

            // no match, return null.
            return null;
        }
    
        private static T ConvertParameter<T>(this object value)
        {
            if (value == null || object.Equals(value, default(T)))
            {
                return default(T);
            }

            PSObject PSObj = value as PSObject;

            if (PSObj != null)
            {
                return PSObj.BaseObject.ConvertParameter<T>();
            }

            if (value is T)
            {
                if (typeof(T) == typeof(string))
                {
                    //Remove quotes from string values taken from the command line
                    // value = value.ToString().Trim('"').Trim('\'');
                }
                return (T)value;
            }

            var constructorInfo = typeof(T).GetConstructor(new[] { value.GetType() });

            if (constructorInfo != null)
            {
                return (T)constructorInfo.Invoke(new[] { value });
            }

            try
            {
                return (T)Convert.ChangeType(value, typeof(T));
            }
            catch (Exception)
            {
                return default(T);
            }
        }    
    }
}
"@