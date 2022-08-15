#Set Directories to Scan
param (
$TargetDir
)

if($TargetDir -eq $null)
{
    $TargetBins = Get-ChildItem -Path $env:HOMEDRIVE\Users , $env:HOMEDRIVE\ProgramData, $env:HOMEDRIVE\Intel, $env:HOMEDRIVE\Recovery -Force -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue 
    $TargetDLLs = Get-ChildItem -Path $env:HOMEDRIVE\Users , $env:HOMEDRIVE\ProgramData, $env:HOMEDRIVE\Intel, $env:HOMEDRIVE\Recovery -Force -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".dll")} -ErrorAction SilentlyContinue
    write-host "Analyzing DLL/EXE metadata in Users, ProgramData, Intel, Recovery directories"
}
else
{
    $TargetBins = Get-ChildItem -Path "$TargetDir" -Force -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue 
    $TargetDLLs = Get-ChildItem -Path "$TargetDir" -Force -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".dll")} -ErrorAction SilentlyContinue
    write-host "Analyzing DLL/EXE metadata in: " $TargetDir
}


#Importing Get-Hash helper function for ps2 systems from jaredcatkinson. Credit: https://gist.github.com/jaredcatkinson/7d561b553a04501238f8e4f061f112b7
function Get-Hash
{
    <#
    .SYNOPSIS
    Get-Hash is a PowerShell Version 2 port of Get-FileHash that supports hashing files, as well as, strings.
    .PARAMETER InputObject
    This is the actual item used to calculate the hash. This value will support [Byte[]] or [System.IO.Stream] objects.
    .PARAMETER FilePath
    Specifies the path to a file to hash. Wildcard characters are permitted.
    .PARAMETER Text
    A string to calculate a cryptographic hash for.
    .PARAMETER Encoding
    Specified the character encoding to use for the string passed to the Text parameter. The default encoding type is Unicode. The acceptable values for this parameter are:
    - ASCII
    - BigEndianUnicode
    - Default
    - Unicode
    - UTF32
    - UTF7
    - UTF8
    .PARAMETER Algorithm
    Specifies the cryptographic hash function to use for computing the hash value of the contents of the specified file. A cryptographic hash function includes the property that it is not possible to find two distinct inputs that generate the same hash values. Hash functions are commonly used with digital signatures and for data integrity. The acceptable values for this parameter are:
    
    - SHA1
    - SHA256
    - SHA384
    - SHA512
    - MACTripleDES
    - MD5
    - RIPEMD160
    
    If no value is specified, or if the parameter is omitted, the default value is SHA256.
    For security reasons, MD5 and SHA1, which are no longer considered secure, should only be used for simple change validation, and should not be used to generate hash values for files that require protection from attack or tampering.
    .NOTES
    
    This function was adapted from https://p0w3rsh3ll.wordpress.com/2015/02/05/backporting-the-get-filehash-function/
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    .EXAMPLE
    Get-Hash -Text 'This is a string'
    .EXAMPLE
    Get-Hash -FilePath C:\This\is\a\filepath.exe
    #>

    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        [ValidateNotNullOrEmpty()]
        $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Text')]
        [string]
        [ValidateNotNullOrEmpty()]
        $Text,

        [Parameter(ParameterSetName = 'Text')]
        [string]
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Default', 'Unicode', 'UTF32', 'UTF7', 'UTF8')]
        $Encoding = 'Unicode',

        [Parameter()]
        [string]
        [ValidateSet("MACTripleDES", "MD5", "RIPEMD160", "SHA1", "SHA256", "SHA384", "SHA512")]
        $Algorithm = "SHA256"
    )

    switch($PSCmdlet.ParameterSetName)
    {
        File
        {
            try
            {
                $FullPath = Resolve-Path -Path $FilePath -ErrorAction Stop
                $InputObject = [System.IO.File]::OpenRead($FilePath)
                Get-Hash -InputObject $InputObject -Algorithm $Algorithm
            }
            catch
            {
                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $null
                }
            }
        }
        Text
        {
            $InputObject = [System.Text.Encoding]::$Encoding.GetBytes($Text)
            Get-Hash -InputObject $InputObject -Algorithm $Algorithm
        }
        Object
        {
            if($InputObject.GetType() -eq [Byte[]] -or $InputObject.GetType().BaseType -eq [System.IO.Stream])
            {
                # Construct the strongly-typed crypto object
                $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)

                # Compute file-hash using the crypto object
                [Byte[]] $computedHash = $Hasher.ComputeHash($InputObject)
                [string] $hash = [BitConverter]::ToString($computedHash) -replace '-',''

                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                }

                $retVal
            }
        }
    }
}

##Start Shimcache Functions
function Get-SusShimCachePS45
{
    ## Importing Helper Functions from PS-DigitalForensics https://github.com/davidhowell-tx/PS-DigitalForensics Credit: David Howell ##
    write-host "Analyzing Program Execution Evidence"
    $SusShimCacheArray = @()
    $count = 0
    # Initialize Array to store our data
$EntryArray=@()
$AppCompatCache=$Null

switch($PSCmdlet.ParameterSetName) {
	"Path" {
		if (Test-Path -Path $Path) {
			# Get the Content of the .reg file, only return lines with Hexadecimal values on them, and remove the backslashes, spaces, and wording at the start
			$AppCompatCache = Get-Content -Path $Path | Select-String -Pattern "[A-F0-9][A-F0-9]," | ForEach-Object { $_ -replace "(\\|,|`"AppCompatCache`"=hex:|\s)","" }
			# Join all of the hexadecimal into one big string
			$AppCompatCache = $AppCompatCache -join ""
			# Convert the Hexadecimal string to a byte array
			$AppCompatCache = $AppCompatCache -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [System.Convert]::ToByte( $_, 16 ) }
			# Thanks to beefycode for that code snippet: http://www.beefycode.com/post/Convert-FromHex-PowerShell-Filter.aspx
		}
	}
	
	Default {
		if (!(Get-PSDrive -Name HKLM -PSProvider Registry)) {
			New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE
		}
		# This command gets the current AppCompat Cache, and returns it in a Byte Array.
		if (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatCache\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppCompatCache) {
			# This is the Windows 2003 and later location of AppCompatCache in the registry
			$AppCompatCache = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatCache\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppCompatCache
		} else {
			# If the normal area is not available, try the Windows XP location.
			# Note, this piece is untested as I don't have a Windows XP system to work with.
			$AppCompatCache = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppCompatCache
		}
	}
}

if ($AppCompatCache -ne $null) {

	# Initialize a Memory Stream and Binary Reader to scan through the Byte Array
	$MemoryStream = New-Object System.IO.MemoryStream(,$AppCompatCache)
	$BinReader = New-Object System.IO.BinaryReader $MemoryStream
	$UnicodeEncoding = New-Object System.Text.UnicodeEncoding
	$ASCIIEncoding = New-Object System.Text.ASCIIEncoding

	# The first 4 bytes of the AppCompatCache is a Header.  Lets parse that and use it to determine which format the cache is in.
	$Header = ([System.BitConverter]::ToString($BinReader.ReadBytes(4))) -replace "-",""

	switch ($Header) {

       # 0x34 - Windows 10 Creators update
        "34000000" {
                
                #read past header
                $BinReader.ReadBytes(48) | Out-Null
            
                #$NumberOfEntries = 760 # can't locate the number of entries in header - read until error
                $EntryNum = 0
                while($True){
                    try{
                        $TempObject = "" | Select-Object -Property Name, Time, Data, EntryNumber
                        $TempObject | Add-Member -MemberType NoteProperty -Name "Tag" -Value ($ASCIIEncoding.GetString($BinReader.ReadBytes(4)))
                        $BinReader.ReadBytes(4) | Out-Null
                        $CacheEntrySize = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
                        $NameLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
                        # This probably needs to be NameLength * 2 if the length is the number of unicode characters - need to verify
                        
                        $TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($NameLength))
                        #write-host $TempObject.FileName #dbg
                        $TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
                        $DataLength = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
                        $TempObject.Data = $ASCIIEncoding.GetString($BinReader.ReadBytes($DataLength))
                        $TempObject.EntryNumber = $EntryNum
                        $EntryArray += $TempObject
                        $EntryNum++
                    }catch{
                        break
                    }
                    
                }
                #return

                
            }

		# 0x30 - Windows 10
		"30000000" {
			# Finish Reading Header
			$BinReader.ReadBytes(32) | Out-Null
			$NumberOfEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			$BinReader.ReadBytes(8) | Out-Null
			
			# Complete loop to parse each entry
			for ($i=0; $i -lt $NumberOfEntries; $i++) {
				$TempObject = "" | Select-Object -Property Name, LastModifiedTime, Data
				$TempObject | Add-Member -MemberType NoteProperty -Name "Tag" -Value ($ASCIIEncoding.GetString($BinReader.ReadBytes(4)))
				$BinReader.ReadBytes(4) | Out-Null
				$CacheEntrySize = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
				$NameLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
				# This probably needs to be NameLength * 2 if the length is the number of unicode characters - need to verify
				$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($NameLength))
				$TempObject.LastModifiedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				$DataLength = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
				$TempObject.Data = $ASCIIEncoding.GetString($BinReader.ReadBytes($DataLength))
				$EntryArray += $TempObject
			}
                #$EntryArray | Select Name, LastModifiedTime
                write-host "win 10"
		}
	
		# 0x80 - Windows 8
		"80000000" {
			$Offset = [System.BitConverter]::ToUInt32($AppCompatCache[0..3],0)
			$Tag = [System.BitConverter]::ToString($AppCompatCache[$Offset..($Offset+3)],0) -replace "-",""
			
			if ($Tag -eq "30307473" -or $Tag -eq "31307473") {
				# 64-bit
				$MemoryStream.Position = ($Offset)
				
				# Complete loop to parse each entry
				while ($MemoryStream.Position -lt $MemoryStream.Length) {
					# I've noticed some random gaps of space in Windows 8 AppCompatCache
					# We need to verify the tag for each entry
					# If the tag isn't correct, read through until the next correct tag is found
					
					# First 4 Bytes is the Tag
					$EntryTag = [System.BitConverter]::ToString($BinReader.ReadBytes(4),0) -replace "-",""
					
					if ($EntryTag -eq "30307473" -or $EntryTag -eq "31307473") {
						# Skip 4 Bytes
						$BinReader.ReadBytes(4) | Out-Null
						$TempObject = "" | Select-Object -Property Name, Time
						$JMP = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$SZ = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($SZ + 2))
						$BinReader.ReadBytes(8) | Out-Null
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$BinReader.ReadBytes(4) | Out-Null
						$TempObject
					} else {
						# We've found a gap of space that isn't an AppCompatCache Entry
						# Perform a loop to read 1 byte at a time until we find the tag 30307473 or 31307473 again
						$Exit = $False
						
						while ($Exit -ne $true) {
							$Byte1 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
							if ($Byte1 -eq "30" -or $Byte1 -eq "31") {
								$Byte2 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
								if ($Byte2 -eq "30") {
									$Byte3 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
									if ($Byte3 -eq "74") {
										$Byte4 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
										if ($Byte4 -eq "73") {
											# Verified a correct tag for a new entry
											# Scroll back 4 bytes and exit the scan loop
											$MemoryStream.Position = ($MemoryStream.Position - 4)
											$Exit = $True
										} else {
											$MemoryStream.Position = ($MemoryStream.Position - 3)
										}
									} else {
										$MemoryStream.Position = ($MemoryStream.Position - 2)
									}
								} else {
									$MemoryStream.Position = ($MemoryStream.Position - 1)
								}
							}
						}
					}
				}
				
			} elseif ($Tag -eq "726F7473") {
				# 32-bit
				
				$MemoryStream.Position = ($Offset + 8)
				
				# Complete loop to parse each entry
				while ($MemoryStream.Position -lt $MemoryStream.Length) {
					#Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property Name, Time
					
					$JMP = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$SZ = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($SZ))
					$EntryArray += $TempObject
				}
			}
			#$EntryArray | Select-Object -Property Name, Time
            write-host "win 8"

		}
	
		# BADC0FEE in Little Endian Hex - Windows 7 / Windows 2008 R2
		"EE0FDCBA" {
			# Number of Entries at Offset 4, Length of 4 bytes
			$NumberOfEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			# Move BinReader to the Offset 128 where the Entries begin
			$MemoryStream.Position=128
			
			# Get some baseline info about the 1st entry to determine if we're on 32-bit or 64-bit OS
			$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
			$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
			$Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			
			# Move Binary Reader back to the start of the entries
			$MemoryStream.Position=128
			
			if (($MaxLength - $Length) -eq 2) {
				if ($Padding -eq 0) {
					# 64-bit Operating System
					
					# Use the Number of Entries it says are available and iterate through this loop that many times
					for ($i=0; $i -lt $NumberOfEntries; $i++) {
						# Parse the metadata for the entry and add to a custom object
						$TempObject = "" | Select-Object -Property Name, Length, MaxLength, Padding, Offset0, Offset1, Time, Flag0, Flag1
						$TempObject.Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Offset0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Offset1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# calculate the modified date/time in this QWORD
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$TempObject.Flag0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Flag1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# Use the Offset and the Length to read the File Name
						$TempObject.Name = ($UnicodeEncoding.GetString($AppCompatCache[$TempObject.Offset0..($TempObject.Offset0+$TempObject.Length-1)])) -replace "\\\?\?\\",""
						# Seek past the 16 Null Bytes at the end of the entry header
						# This is Blob Size and Blob Offset according to: https://dl.mandiant.com/EE/library/Whitepaper_ShimCacheParser.pdf
						$Nothing = $BinReader.ReadBytes(16)
						$EntryArray += $TempObject
					}
				} else {
					# 32-bit Operating System
					
					# Use the Number of Entries it says are available and iterate through this loop that many times
					for ($i=0; $i -lt $NumberOfEntries; $i++) {
						# Parse the metadata for the entry and add to a custom object
						$TempObject = "" | Select-Object -Property Name, Length, MaxLength, Offset, Time, Flag0, Flag1
						$TempObject.Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# calculate the modified date/time in this QWORD
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$TempObject.Flag0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Flag1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# Use the Offset and the Length to read the File Name
						$TempObject.Name = ($UnicodeEncoding.GetString($AppCompatCache[$TempObject.Offset0..($TempObject.Offset0+$TempObject.Length-1)])) -replace "\\\?\?\\",""
						# Seek past the 16 Null Bytes at the end of the entry header
						# This is Blob Size and Blob Offset according to: https://dl.mandiant.com/EE/library/Whitepaper_ShimCacheParser.pdf
						$Nothing = $BinReader.ReadBytes(16)
						$EntryArray += $TempObject
					}
					
				}
			}
			
			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			#$EntryArray | Format-Table -AutoSize -Property Name, Time
            write-host "win 7"
		}
		
		# BADC0FFE in Little Endian Hex - Windows XP 64-bit, Windows Server 2003 through Windows Vista and Windows Server 2008
		"FE0FDCBA" {
		#### THIS AREA NEEDS WORK, TESTING, ETC.
		
			# Number of Entries at Offset 4, Length of 4 bytes
			$NumberOfEntries = [System.BitConverter]::ToUInt32($AppCompatCache[4..7],0)
			
			# Lets analyze the padding of the first entry to determine if we're on 32-bit or 64-bit OS
			$Padding = [System.BitConverter]::ToUInt32($AppCompatCache[12..15],0)
			
			# Move BinReader to the Offset 8 where the Entries begin
			$MemoryStream.Position=8
			
			if ($Padding -eq 0) {
				# 64-bit Operating System
				
				# Use the Number of Entries it says are available and iterate through this loop that many times
				for ($i=0; $i -lt $NumberOfEntries; $i++) {
					# Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property Name, Time, FileSize, Executed
					$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$BinReader.ReadBytes(4) | Out-Null
					$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$TempObject.FileSize = [System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)
					$TempObject.Name = $Unicode.GetString($AppCompatCache[$Offset..($Offset + $Length)])
					if ($TempObject.FileSize -gt 0) {
						$TempObject.Executed = $True
					} else {
						$TempObject.Executed = $False
					}
					$EntryArray += $TempObject
					Remove-Variable Length
					Remove-Variable Padding
					Remove-Variable MaxLength
					Remove-Variable Offset
					Remove-Variable TempObject
				}
			} else {
				# 32-bit Operating System
				
				# Use the Number of Entries it says are available and iterate through this loop that many times
				for ($i=0; $i -lt $NumberOfEntries; $i++) {
					# Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property FileName, Time, FileSize
					$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$TempObject.FileSize = [System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)
					$TempObject.FileName = $Unicode.GetString($AppCompatCache[$Offset..($Offset + $Length)])
					$EntryArray += $TempObject
					Remove-Variable Length
					Remove-Variable MaxLength
					Remove-Variable Offset
					Remove-Variable TempObject
				}
			}
			
			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			#$EntryArray | Format-Table -AutoSize -Property Name, Time
            write-host "win xp 64"

		}
		
		# DEADBEEF in Little Endian Hex - Windows XP 32-bit
		"EFBEADDE" {
			# Number of Entries
			$NumberOfEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			# Number of LRU Entries
			$NumberOfLRUEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			# Unknown
			$BinReader.ReadBytes(4) | Out-Null
			# LRU Array Start
			for ($i=0; $i -lt $NumberOfLRUEntries; $i++) {
				$LRUEntry
			}
			
			# Move to the Offset 400 where the Entries begin
			$MemoryStream.Position=400
			
			# Use the Number of Entries it says are available and iterate through this loop that many times
			for ($i=0; $i -lt $NumberOfEntries; $i++) {
				# Parse the metadata for the entry and add to a custom object
				$TempObject = "" | Select-Object -Property FileName, LastModifiedTime, Size, LastUpdatedTime
				# According to Mandiant paper, MAX_PATH + 4 (260 + 4, in unicode = 528 bytes)
				$TempObject.FileName = ($UnicodeEncoding.GetString($BinReader.ReadBytes(528))) -replace "\\\?\?\\",""
				$TempObject.LastModifiedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				# I'm not fully confident in the Size value without having a Windows XP box to test. Mandiant Whitepaper only says Large_Integer, QWORD File Size. Harlan Carveys' script parses as 2 DWORDS.
				$TempObject.FileSize = [System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)
				$TempObject.LastUpdatedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				$EntryArray += $TempObject
			}
			
			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			#return $EntryArray
            write-host "win xp 32 bit"
		}
	}
        foreach($Entry in $EntryArray)
        {
           $ShimFileName = Split-Path $Entry.Name -leaf
           $check=""
           $check64=""           
           if(($ShimFileName -ne "dismhost.exe") -and ($Entry.Name))
           {
           if($64BinsOnly.InputObject -contains $ShimFileName)
           {
                [array]$check = $Sys64BinList | where {$_.Name -eq $ShimFileName}
                
                if($check.Length -gt 1)
                {
                        foreach($bin in $check)
                        {
                            [string]$stringpath = $Entry.Name
                            if (($bin.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                            {
           
                                $SusShimCacheObject = New-Object psobject
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $bin.Name
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $check.FullName
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSys64Match" -Value $check64.FullName
                                $SusShimCacheArray += $SusShimCacheObject
                            }
                        }
                 }
                 if($check.Length -eq 1)
                 {
                        
                        [string]$stringpath = $Entry.Name
                        if (($check.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                        {
           
                            $SusShimCacheObject = New-Object psobject
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $Entry.Name
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $check.FullName
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSys64Match" -Value $check64.FullName
                            $SusShimCacheArray += $SusShimCacheObject
                        }
                 }

           }
           elseif ($Sys32BinList.Name -contains $ShimFileName)
           {
                [array]$check = $Sys32BinList | where {$_.Name -eq $ShimFileName}
                if ($Sys64BinList.Name -contains $ShimFileName)
                {
                    [array]$check64 = $Sys64BinList | where {$_.Name -eq $ShimFileName}
                }
                
                if($check.Length -gt 1)
                {
                        
                        foreach($bin in $check)
                        {
                            [string]$stringpath = $Entry.Name
                            if($check64)
                            {

                               
                                if (($bin.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0) -and ($check64.FullName.ToLower() -ne $stringpath.ToLower()))
                                {
                                
                                    $SusShimCacheObject = New-Object psobject
                                    $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                                    $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $stringpath
                                    $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $bin.FullName
                                    $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSys64Match" -Value $check64.FullName
                                    $SusShimCacheArray += $SusShimCacheObject

                                }


                            }
                            elseif (($bin.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                            {
                                
                                $SusShimCacheObject = New-Object psobject
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $stringpath
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $bin.FullName
                                $SusShimCacheArray += $SusShimCacheObject
                             }
                        }
                }
                if($check.Length -eq 1)
                {
                        [string]$stringpath = $Entry.Name
                        
                        if($check64)
                        {
                                          
                            if (($check.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0) -and ($check64.FullName.ToLower() -ne $stringpath.ToLower()))
                            {
                            $SusShimCacheObject = New-Object psobject
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $stringpath
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $check.FullName
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "Win64SysMatch" -Value $check64.FullName
                            $SusShimCacheArray += $SusShimCacheObject
                            }

                        }
                        elseif (($check.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                        {
                            $SusShimCacheObject = New-Object psobject
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $stringpath
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $check.FullName
                            $SusShimCacheArray += $SusShimCacheObject
                        }
                }
           }
           }
        }
        $SusShimCacheArray | Export-csv -NoTypeInformation $CollectionPath\SuspiciousShimCacheEntries.csv  
}


}

function Get-SusShimCachePS23
{
    ## Importing Helper Functions from PS-DigitalForensics https://github.com/davidhowell-tx/PS-DigitalForensics Credit: David Howell ##
    write-host "Analyzing Program Execution Evidence"
    $SusShimCacheArray = @()
    $count = 0


    # Initialize Array to store our data
    $EntryArray=@()
    $AppCompatCache=$Null

switch($PSCmdlet.ParameterSetName) {
	"Path" {
		if (Test-Path -Path $Path) {
			# Get the Content of the .reg file, only return lines with Hexadecimal values on them, and remove the backslashes, spaces, and wording at the start
			$AppCompatCache = Get-Content -Path $Path | Select-String -Pattern "[A-F0-9][A-F0-9]," | ForEach-Object { $_ -replace "(\\|,|`"AppCompatCache`"=hex:|\s)","" }
			# Join all of the hexadecimal into one big string
			$AppCompatCache = $AppCompatCache -join ""
			# Convert the Hexadecimal string to a byte array
			$AppCompatCache = $AppCompatCache -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [System.Convert]::ToByte( $_, 16 ) }
			# Thanks to beefycode for that code snippet: http://www.beefycode.com/post/Convert-FromHex-PowerShell-Filter.aspx
		}
	}
	
	Default {
		if (!(Get-PSDrive -Name HKLM -PSProvider Registry)) {
			New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE
		}
		# This command gets the current AppCompat Cache, and returns it in a Byte Array.
		if (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatCache\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppCompatCache) {
			# This is the Windows 2003 and later location of AppCompatCache in the registry
			$AppCompatCache = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatCache\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppCompatCache
            $AppCompatPath = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatCache\' -ErrorAction SilentlyContinue 
            $AppCompatPath = $AppCompatPath.PSPath.ToString()
		} else {
			# If the normal area is not available, try the Windows XP location.
			# Note, this piece is untested as I don't have a Windows XP system to work with.
			$AppCompatCache = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppCompatCache
            $AppCompatPath = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache' -ErrorAction SilentlyContinue 
            $AppCompatPath = $AppCompatPath.PSPath.ToString()
		}
	}
}

Write-Host "Collecting Shimcache for $env:ComputerName"
write-host $AppCompatPath


if ($AppCompatCache -ne $null) {

	# Initialize a Memory Stream and Binary Reader to scan through the Byte Array
	$MemoryStream = New-Object System.IO.MemoryStream(,$AppCompatCache)
	$BinReader = New-Object System.IO.BinaryReader $MemoryStream
	$UnicodeEncoding = New-Object System.Text.UnicodeEncoding
	$ASCIIEncoding = New-Object System.Text.ASCIIEncoding

	# The first 4 bytes of the AppCompatCache is a Header.  Lets parse that and use it to determine which format the cache is in.
	$Header = ([System.BitConverter]::ToString($BinReader.ReadBytes(4))) -replace "-",""

	switch ($Header) {
    #Windows 8
        "80000000" {
			$Offset = [System.BitConverter]::ToUInt32($AppCompatCache[0..3],0)
			$Tag = [System.BitConverter]::ToString($AppCompatCache[$Offset..($Offset+3)],0) -replace "-",""
			
			if ($Tag -eq "30307473" -or $Tag -eq "31307473") {
				# 64-bit
				$MemoryStream.Position = ($Offset)
				
				# Complete loop to parse each entry
				while ($MemoryStream.Position -lt $MemoryStream.Length) {
					# I've noticed some random gaps of space in Windows 8 AppCompatCache
					# We need to verify the tag for each entry
					# If the tag isn't correct, read through until the next correct tag is found
					
					# First 4 Bytes is the Tag
					$EntryTag = [System.BitConverter]::ToString($BinReader.ReadBytes(4),0) -replace "-",""
					
					if ($EntryTag -eq "30307473" -or $EntryTag -eq "31307473") {
						# Skip 4 Bytes
						$BinReader.ReadBytes(4) | Out-Null
						$TempObject = "" | Select-Object -Property Name, Time
						$JMP = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$SZ = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($SZ + 2))
						$BinReader.ReadBytes(8) | Out-Null
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$BinReader.ReadBytes(4) | Out-Null
						$TempObject
					} else {
						# We've found a gap of space that isn't an AppCompatCache Entry
						# Perform a loop to read 1 byte at a time until we find the tag 30307473 or 31307473 again
						$Exit = $False
						
						while ($Exit -ne $true) {
							$Byte1 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
							if ($Byte1 -eq "30" -or $Byte1 -eq "31") {
								$Byte2 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
								if ($Byte2 -eq "30") {
									$Byte3 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
									if ($Byte3 -eq "74") {
										$Byte4 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
										if ($Byte4 -eq "73") {
											# Verified a correct tag for a new entry
											# Scroll back 4 bytes and exit the scan loop
											$MemoryStream.Position = ($MemoryStream.Position - 4)
											$Exit = $True
										} else {
											$MemoryStream.Position = ($MemoryStream.Position - 3)
										}
									} else {
										$MemoryStream.Position = ($MemoryStream.Position - 2)
									}
								} else {
									$MemoryStream.Position = ($MemoryStream.Position - 1)
								}
							}
						}
					}
				}
				
			} elseif ($Tag -eq "726F7473") {
				# 32-bit
				
				$MemoryStream.Position = ($Offset + 8)
				
				# Complete loop to parse each entry
				while ($MemoryStream.Position -lt $MemoryStream.Length) {
					#Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property Name, Time
					
					$JMP = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$SZ = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($SZ))
					$EntryArray += $TempObject
				}
			}
			#$EntryArray | Select Name, Time
		}
		# BADC0FEE in Little Endian Hex - Windows 7 / Windows 2008 R2
		"EE0FDCBA" {
			# Number of Entries at Offset 4, Length of 4 bytes
			$NumberOfEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			# Move BinReader to the Offset 128 where the Entries begin
			$MemoryStream.Position=128
			
			# Get some baseline info about the 1st entry to determine if we're on 32-bit or 64-bit OS
			$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
			$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
			$Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			
			# Move Binary Reader back to the start of the entries
			$MemoryStream.Position=128
			
			if (($MaxLength - $Length) -eq 2) {
				if ($Padding -eq 0) {
					# 64-bit Operating System
					
					# Use the Number of Entries it says are available and iterate through this loop that many times
					for ($i=0; $i -lt $NumberOfEntries; $i++) {
						# Parse the metadata for the entry and add to a custom object
						$TempObject = "" | Select-Object -Property Name, Length, MaxLength, Padding, Offset0, Offset1, Time, Flag0, Flag1
						$TempObject.Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Offset0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Offset1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# calculate the modified date/time in this QWORD
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$TempObject.Flag0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Flag1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# Use the Offset and the Length to read the File Name
						$TempObject.Name = ($UnicodeEncoding.GetString($AppCompatCache[$TempObject.Offset0..($TempObject.Offset0+$TempObject.Length-1)])) -replace "\\\?\?\\",""
						# Seek past the 16 Null Bytes at the end of the entry header
						# This is Blob Size and Blob Offset according to: https://dl.mandiant.com/EE/library/Whitepaper_ShimCacheParser.pdf
						$Nothing = $BinReader.ReadBytes(16)
						$EntryArray += $TempObject
					}
				} else {
					# 32-bit Operating System
					
					# Use the Number of Entries it says are available and iterate through this loop that many times
					for ($i=0; $i -lt $NumberOfEntries; $i++) {
						# Parse the metadata for the entry and add to a custom object
						$TempObject = "" | Select-Object -Property Name, Length, MaxLength, Offset, Time, Flag0, Flag1
						$TempObject.Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# calculate the modified date/time in this QWORD
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$TempObject.Flag0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Flag1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# Use the Offset and the Length to read the File Name
						$TempObject.Name = ($UnicodeEncoding.GetString($AppCompatCache[$TempObject.Offset0..($TempObject.Offset0+$TempObject.Length-1)])) -replace "\\\?\?\\",""
						# Seek past the 16 Null Bytes at the end of the entry header
						# This is Blob Size and Blob Offset according to: https://dl.mandiant.com/EE/library/Whitepaper_ShimCacheParser.pdf
						$Nothing = $BinReader.ReadBytes(16)
						$EntryArray += $TempObject
					}
					
				}
			}
			
			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			#$EntryArray | Format-Table -AutoSize -Property Name, Time, Flag0, Flag1
		}
		
		# BADC0FFE in Little Endian Hex - Windows XP 64-bit, Windows Server 2003 through Windows Vista and Windows Server 2008
		"FE0FDCBA" {
		#### THIS AREA NEEDS WORK, TESTING, ETC.
		
			# Number of Entries at Offset 4, Length of 4 bytes
			$NumberOfEntries = [System.BitConverter]::ToUInt32($AppCompatCache[4..7],0)
			
			# Lets analyze the padding of the first entry to determine if we're on 32-bit or 64-bit OS
			$Padding = [System.BitConverter]::ToUInt32($AppCompatCache[12..15],0)
			
			# Move BinReader to the Offset 8 where the Entries begin
			$MemoryStream.Position=8
			
			if ($Padding -eq 0) {
				# 64-bit Operating System
				
				# Use the Number of Entries it says are available and iterate through this loop that many times
				for ($i=0; $i -lt $NumberOfEntries; $i++) {
					# Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property Name, ModifiedTime, FileSize, Executed
					$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$BinReader.ReadBytes(4) | Out-Null
					$TempObject.ModifiedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$TempObject.FileSize = [System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)
					$TempObject.Name = $Unicode.GetString($AppCompatCache[$Offset..($Offset + $Length)])
					if ($TempObject.FileSize -gt 0) {
						$TempObject.Executed = $True
					} else {
						$TempObject.Executed = $False
					}
					$EntryArray += $TempObject
					Remove-Variable Length
					Remove-Variable Padding
					Remove-Variable MaxLength
					Remove-Variable Offset
					Remove-Variable TempObject
				}
			} else {
				# 32-bit Operating System
				
				# Use the Number of Entries it says are available and iterate through this loop that many times
				for ($i=0; $i -lt $NumberOfEntries; $i++) {
					# Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property FileName, ModifiedTime, FileSize
					$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.ModifiedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$TempObject.FileSize = [System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)
					$TempObject.FileName = $Unicode.GetString($AppCompatCache[$Offset..($Offset + $Length)])
					$EntryArray += $TempObject
					Remove-Variable Length
					Remove-Variable MaxLength
					Remove-Variable Offset
					Remove-Variable TempObject
				}
			}
			
			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			#$EntryArray | Format-Table -AutoSize -Property Name, Time, Flag0, Flag1
		}
		
		# DEADBEEF in Little Endian Hex - Windows XP 32-bit
		"EFBEADDE" {
			# Number of Entries
			$NumberOfEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			# Number of LRU Entries
			$NumberOfLRUEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			# Unknown
			$BinReader.ReadBytes(4) | Out-Null
			# LRU Array Start
			for ($i=0; $i -lt $NumberOfLRUEntries; $i++) {
				$LRUEntry
			}
			
			# Move to the Offset 400 where the Entries begin
			$MemoryStream.Position=400
			
			# Use the Number of Entries it says are available and iterate through this loop that many times
			for ($i=0; $i -lt $NumberOfEntries; $i++) {
				# Parse the metadata for the entry and add to a custom object
				$TempObject = "" | Select-Object -Property Name, LastModifiedTime, Size, LastUpdatedTime
				# According to Mandiant paper, MAX_PATH + 4 (260 + 4, in unicode = 528 bytes)
				$TempObject.Name = ($UnicodeEncoding.GetString($BinReader.ReadBytes(528))) -replace "\\\?\?\\",""
				$TempObject.LastModifiedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				# I'm not fully confident in the Size value without having a Windows XP box to test. Mandiant Whitepaper only says Large_Integer, QWORD File Size. Harlan Carveys' script parses as 2 DWORDS.
				$TempObject.FileSize = [System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)
				$TempObject.LastUpdatedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				$EntryArray += $TempObject
			}
			
			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			#return $EntryArray
		}

	}

    foreach($Entry in $EntryArray)
    {
           $ShimFileName = Split-Path $Entry.Name -leaf
           $check=""
           $check64=""
           if(@($64BinsOnly| %{$_.InputObject}) -contains $ShimFileName)
           {
                [array]$check = $Sys64BinList | where {$_.Name -eq $ShimFileName}
                if($check.Length -gt 1)
                {
                        foreach($bin in $check)
                        {
                            [string]$checkps2 = @($bin| %{$_.FullName})
                            [string]$stringpath = $Entry.Name
                            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                            {
           
                                $SusShimCacheObject = New-Object psobject
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $stringpath
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                                $SusShimCacheArray += $SusShimCacheObject
                            }
                        }
                 }
                 if($check.Length -eq 1)
                 {
                        
                        [string]$stringpath = $Entry.Name
                        if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                        {
           
                            $SusShimCacheObject = New-Object psobject
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $Entry.Name
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                            $SusShimCacheArray += $SusShimCacheObject
                        }
                 }
           }
           elseif (@($Sys32BinList| %{$_.Name}) -contains $ShimFileName)
           {
                [array]$check = $Sys32BinList | where {$_.Name -eq $ShimFileName}
                [string]$checkps2 = @($check| %{$_.FullName})
                if (@($Sys64BinList| %{$_.Name}) -contains $ShimFileName)
                {
                    [array]$check64 = $Sys64BinList | where {$_.Name -eq $ShimFileName}
                    [string]$check64ps2 = @($check64 | %{$_.FullName})
                }
                
                if($check.Length -gt 1)
                {
                        
                        foreach($bin in $check)
                        {
                            [string]$stringpath = $bin.Name
                            [string]$checkps2 = @($bin| %{$_.FullName})
                            if($check64)
                            {
                                if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0) -and ($checkps264.ToLower() -ne $stringpath.ToLower()))
                                {
                                $SusShimCacheObject = New-Object psobject
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $bin.Name
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSys64Match" -Value $check64ps2
                                $SusShimCacheArray += $SusShimCacheObject
                                }
                            }
                            elseif (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                            {
                                
                                $SusShimCacheObject = New-Object psobject
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $bin.Name
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                                $SusShimCacheArray += $SusShimCacheObject
                             }
                        }
                }
                if($check.Length -eq 1)
                {
                        [string]$stringpath = $Entry.Name
                        
                        if($check64)
                        {
                                                      
                            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0) -and ($check64ps2.ToLower() -ne $stringpath.ToLower()))
                            {
      
                            $SusShimCacheObject = New-Object psobject
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $Entry.Name
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSys64Match" -Value $check64ps2
                            $SusShimCacheArray += $SusShimCacheObject
                            }
                        }
                        elseif (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                        {

                            $SusShimCacheObject = New-Object psobject
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $Entry.Name
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                            $SusShimCacheArray += $SusShimCacheObject
                        }
                }
           }
            
    }
    $SusShimCacheArray | Export-csv -NoTypeInformation $CollectionPath\SuspiciousShimCacheEntries.csv  
}

}
##End Shimcache Functions

##Start side load detects
Function Get-SideLoadDetectsPS45
{
 write-host "Searching for evidence of sideloading"
$SideLoadDetectArray = @()
 
$count = 0

foreach($TargetDLL in $TargetDLLs)
{
    
   if ($Sys32DLLList.Name -contains $TargetDLL.Name)
   {
        $TargetDirExes=""
        [array]$check = $Sys32DLLList | where {$_.Name -eq $TargetDLL.Name}
        if($check.Length -gt 1)
        {
            foreach($dll in $check)
            {
                $DllSigResult = Get-AuthenticodeSignature $dll.FullName -ErrorAction Ignore
                $CertSubject = Get-AuthenticodeSignature $dll.FullName | ` Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
                $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                if ($CertSubject.Subject -ne $MSSubject)
                {
                    $TargetDirExes = Get-ChildItem $dll.Directory -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue
                    foreach($TargetDirExe in $TargetDirExes)
                    {
                                              
                        if($TargetDirExe.VersionInfo.OriginalFileName)
                        {
                            [string]$TargetDirExeOGName = $TargetDirExe.VersionInfo.OriginalFileName.replace(".MUI","")
                        }
                        if (($Sys32BinList.Name -contains $TargetDirExeOGName) -or ($Sys32BinList.Name -contains $TargetDirExe.Name))
                        {
                            if ($PSVersionTable.PSVersion.Major -lt 4)
                            {
                                $DllHash = Get-Hash -Algorithm MD5 -FilePath $TargetDLL.FullName -ErrorAction SilentlyContinue
                            }
                            else
                            {
                                $DllHash = Get-FileHash -Algorithm MD5 $TargetDLL.FullName -ErrorAction SilentlyContinue
                            }
                            
                            $SideLoadDetectObject = New-Object psobject
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExe" -Value $TargetDirExe.FullName
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExeOriginalFilename" -Value $TargetDirExe.VersionInfo.OriginalFileName
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadDLL" -Value $dll.FullName
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "DLLHash" -Value $dll.Hash
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SigStatus" -Value $DllSigResult.Status
                            $SideLoadDetectArray += $SideLoadDetectObject
                        }
                    }
                }
            }
        }
        if($check.Length -eq 1)
        {
            
            $DllSigResult = Get-AuthenticodeSignature $TargetDLL.FullName -ErrorAction Ignore
            $CertSubject = Get-AuthenticodeSignature $TargetDLL.FullName | ` Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
            $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
            
                      
               $TargetDirExes = Get-ChildItem $TargetDLL.Directory -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue
               foreach($TargetDirExe in $TargetDirExes)
               {
                if($TargetDirExe.VersionInfo.OriginalFileName)
                {
                      [string]$TargetDirExeOGName = $TargetDirExe.VersionInfo.OriginalFileName.replace(".MUI","")
                }

                if ($CertSubject.Subject -ne $MSSubject)
                {
                    if ($Sys32BinList.Name -contains $TargetDirExeOGName)
                    {
                        if ($PSVersionTable.PSVersion.Major -lt 4)
                            {
                                $DllHash = Get-Hash -Algorithm MD5 -FilePath $TargetDLL.FullName -ErrorAction SilentlyContinue
                            }
                            else
                            {
                                $DllHash = Get-FileHash -Algorithm MD5 $TargetDLL.FullName -ErrorAction SilentlyContinue
                            }
                        $SideLoadDetectObject = New-Object psobject
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExe" -Value $TargetDirExe.FullName
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExeOriginalFilename" -Value $TargetDirExe.VersionInfo.OriginalFileName
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadDLL" -Value $TargetDLL.FullName
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "DLLHash" -Value $DllHash.Hash
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SigStatus" -Value $DllSigResult.Status
                        $SideLoadDetectArray += $SideLoadDetectObject
                    }
                 }
               }
                        
        }
    }
    

}


$SideLoadDetectArray | Export-csv -NoTypeInformation $CollectionPath\SideLoadDetections.csv

# End of PRocess Dump
}

Function Get-SideLoadDetectsPS23
{
write-host "Searching for evidence of sideloading"
$SideLoadDetectArray = @()
$count = 0

foreach($TargetDLL in $TargetDLLs)
{
    
   if (@($Sys32DLLList| %{$_.Name}) -contains $TargetDLL.Name)
   {
        $TargetDirExes=""
        [array]$check = $Sys32DLLList | where {$_.Name -eq $TargetDLL.Name}
        if($check.Length -gt 1)
        {
            foreach($dll in $check)
            {
                $DllSigResult = Get-AuthenticodeSignature $dll.FullName -ErrorAction Ignore
                $CertSubject = Get-AuthenticodeSignature $dll.FullName | ` Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
                $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                if ($CertSubject.Subject -ne $MSSubject)
                {
                    $TargetDirExes = Get-ChildItem $dll.Directory -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue
                    foreach($TargetDirExe in $TargetDirExes)
                    {
                        if($TargetDirExe.VersionInfo.OriginalFileName)
                        {
                            [string]$TargetDirExeOGName = $TargetDirExe.VersionInfo.OriginalFileName.replace(".MUI","")
                        }
                       
                       
                        if ((@($Sys32BinList| %{$_.Name}) -contains $TargetDirExeOGName) -or (@($Sys32BinList| %{$_.Name}) -contains $TargetDirExe.Name))
                        {
                            if ($PSVersionTable.PSVersion.Major -lt 4)
                            {
                                $DllHash = Get-Hash -Algorithm MD5 -FilePath $TargetDLL.FullName -ErrorAction SilentlyContinue
                            }
                            else
                            {
                                $DllHash = Get-FileHash -Algorithm MD5 $TargetDLL.FullName -ErrorAction SilentlyContinue
                            }
                            
                            $SideLoadDetectObject = New-Object psobject
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExe" -Value $TargetDirExe.FullName
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExeOriginalFilename" -Value $TargetDirExeOGName
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadDLL" -Value $dll.FullName
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "DLLHash" -Value $dll.Hash
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SigStatus" -Value $DllSigResult.Status
                            $SideLoadDetectArray += $SideLoadDetectObject
                        }
                    }
                }
            }
        }
        if($check.Length -eq 1)
        {

               $DllSigResult = Get-AuthenticodeSignature $TargetDLL.FullName -ErrorAction Ignore
               $CertSubject = Get-AuthenticodeSignature $TargetDLL.FullName | ` Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
               $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"     
               $TargetDirExes = Get-ChildItem $TargetDLL.Directory -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue
               foreach($TargetDirExe in $TargetDirExes)
               {
                [string]$TargetDirExeName = @($TargetDirExe| %{$_.Name})
                [string]$TargetDirExeFullName = @($TargetDirExe| %{$_.FullName})
                
                if($TargetDirExe.VersionInfo.OriginalFileName)
                {
                    [string]$TargetDirExeOGName = $TargetDirExe.VersionInfo.OriginalFileName.replace(".MUI","")
                }
                
                                
                if ($CertSubject.Subject -ne $MSSubject)
                {

                    if ((@($Sys32BinList| %{$_.Name}) -contains $TargetDirExeOGName) -or (@($Sys32BinList| %{$_.Name}) -contains $TargetDirExe.Name))
                    {
                       
                        if ($PSVersionTable.PSVersion.Major -lt 4)
                            {
                                $DllHash = Get-Hash -Algorithm MD5 -FilePath $TargetDLL.FullName -ErrorAction SilentlyContinue
                            }
                            else
                            {
                                $DllHash = Get-FileHash -Algorithm MD5 $TargetDLL.FullName -ErrorAction SilentlyContinue
                            }
                        
                        $SideLoadDetectObject = New-Object psobject
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExe" -Value $TargetDirExeFullName
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExeOriginalFilename" -Value $TargetDirExeOGName
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadDLL" -Value $TargetDLL.FullName
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "DLLHash" -Value $DllHash.Hash
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SigStatus" -Value $DllSigResult.Status
                        $SideLoadDetectArray += $SideLoadDetectObject
                        
                    }
                 }
               }
                        
        }
    }
    

}


$SideLoadDetectArray | Export-csv -NoTypeInformation $CollectionPath\SideLoadDetections.csv


}

## End Sideload Detects

## Start Suspicious Bin Audit

Function Get-SusExecsPS45
{
write-host "Scanning for system executables not in the default locations"
$SusBinListArray = @()
$ErrorActionPreference = "SilentlyContinue"
$count = 0

#Start Find possible sideloaded exes
foreach($TargetDirBin in $TargetBins)
{
    
        
    if($TargetDirBin.VersionInfo.OriginalFileName)
    {
        [string]$TargetDirExeOGName = $TargetDirBin.VersionInfo.OriginalFileName.replace(".MUI","")
    }
    if(($64BinsOnly.InputObject -contains $TargetDirExeOGName) -or ($64BinsOnly.InputObject -contains $TargetDirBin.Name))
    {
       if ($Sys64BinList.Name -contains $TargetDirExeOGName)
       {
            [array]$check = $Sys64BinList | where {$_.Name -eq $TargetDirBin.VersionInfo.OriginalFileName}
       }
       else
       {
            [array]$check = $Sys64BinList | where {$_.Name -eq $TargetDirBin.Name}
       }
              if($check.Length -gt 1)
       {
            foreach($bin in $check)
            {
                [string]$stringpath = $TargetDirBin.FullName
                if (($bin.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $bin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-Hash -Algorithm MD5 -FilePath $check.FullName -ErrorAction SilentlyContinue
                    }
                    else
                    { 
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $bin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-FileHash -Algorithm MD5 $check.FullName -ErrorAction SilentlyContinue
                    }
                    $SusBinListObject = New-Object psobject
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $bin.FullName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $bin.VersionInfo.OriginalFileName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $TargetDirHash.Hash
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $check.FullName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64BinHash.Hash
                    $SusBinListArray += $SusBinListObject
                }
            }
       }
       if($check.Length -eq 1)
       {
            [string]$stringpath = $TargetDirBin.FullName
            if (($check.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $TargetDirBin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-Hash -Algorithm MD5 -FilePath $check.FullName -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $TargetDirBin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-FileHash -Algorithm MD5 $check.FullName -ErrorAction SilentlyContinue
                    }
            $SusBinListObject = New-Object psobject
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $TargetDirBin.FullName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $TargetDirBin.VersionInfo.OriginalFileName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $TargetDirHash.Hash
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $check.FullName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64BinHash.Hash
            $SusBinListArray += $SusBinListObject
            }
       }
    }
    elseif (($Sys32BinList.Name -contains $TargetDirExeOGName) -or ($Sys32BinList.Name -contains $TargetDirBin.Name))
    {
       if ($Sys32BinList.Name -contains $TargetDirBin.VersionInfo.OriginalFileName)
       {
            [array]$check = $Sys32BinList | where {$_.Name -eq $TargetDirExeOGName }
       }
       else
       {
            [array]$check = $Sys32BinList | where {$_.Name -eq $TargetDirBin.Name}
       }
       if($check.Length -gt 1)
       {
            foreach($bin in $check)
            {
                [string]$stringpath = $TargetDirBin.FullName
                if (($bin.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $bin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-Hash -Algorithm MD5 -FilePath $check.FullName -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $bin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-FileHash -Algorithm MD5 $check.FullName -ErrorAction SilentlyContinue
                    }
                    $SusBinListObject = New-Object psobject
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $bin.FullName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $bin.VersionInfo.OriginalFileName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $TargetDirHash.Hash
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $check.FullName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32BinHash.Hash
                    $SusBinListArray += $SusBinListObject
                }
            }
       }
       if($check.Length -eq 1)
       {
            [string]$stringpath = $TargetDirBin.FullName
            if (($check.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $TargetDirBin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-Hash -Algorithm MD5 -FilePath $check.FullName -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $TargetDirBin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-FileHash -Algorithm MD5 $check.FullName -ErrorAction SilentlyContinue
                    }
            $SusBinListObject = New-Object psobject
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $TargetDirBin.FullName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $TargetDirBin.VersionInfo.OriginalFileName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $TargetDirHash.Hash
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $check.FullName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32BinHash.Hash
            $SusBinListArray += $SusBinListObject
            }
       }
       
       
    }

    
    

}


$SusBinListArray | Export-csv -NoTypeInformation $CollectionPath\SuspiciousBinsList.csv

# End of PRocess Dump
}

Function Get-SusExecsPS23
{
write-host "Scanning for system executables not in the default locations"
$SusBinListArray = @()
$ErrorActionPreference = "SilentlyContinue"
$count = 0

#Start Find possible sideloaded exes
foreach($TargetDirBin in $TargetBins)
{
    
     if($TargetDirBin.VersionInfo.OriginalFileName)
    {
        [string]$TargetDirExeOGName = $TargetDirBin.VersionInfo.OriginalFileName.replace(".MUI","")
    }      
    if((@($64BinsOnly| %{$_.InputObject}) -contains $TargetDirExeOGName) -or (@($64BinsOnly| %{$_.InputObject}) -contains $TargetDirBin.Name))
    {
        if (@($Sys64BinList| %{$_.Name}) -contains $TargetDirExeOGName) 
       { 
            [array]$check = $Sys64BinList | where {$_.Name -eq $TargetDirExeOGName}
       }
       else
       {
            [array]$check = $Sys64BinList | where {$_.Name -eq $TargetDirBin.Name}
       }
       if($check.Length -gt 1)
       {
            foreach($bin in $check)
            {
                
                [string]$stringpath = $TargetDirBin.FullName
                [string]$checkps2 = @($check| %{$_.FullName})
                if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $bin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $bin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
                    $SusBinListObject = New-Object psobject
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $bin.FullName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $bin.VersionInfo.OriginalFileName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $TargetDirHash.Hash
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64BinHash.Hash
                    $SusBinListArray += $SusBinListObject
                }
            }
       }
       if($check.Length -eq 1)
       {
            [string]$stringpath = $TargetDirBin.FullName
            [string]$checkps2 = @($check| %{$_.FullName})
            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $TargetDirBin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $TargetDirBin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
            $SusBinListObject = New-Object psobject
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $TargetDirBin.FullName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $TargetDirBin.VersionInfo.OriginalFileName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $TargetDirHash.Hash
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64BinHash.Hash
            $SusBinListArray += $SusBinListObject
            }
       }
    }
    elseif ((@($Sys32BinList| %{$_.Name}) -contains $TargetDirExeOGName) -or (@($Sys32BinList| %{$_.Name}) -contains $TargetDirBin.Name))
    {
       if (@($Sys32BinList| %{$_.Name}) -contains $TargetDirExeOGName)
       {
            [array]$check = $Sys32BinList | where {$_.Name -eq $TargetDirExeOGName}
       }
       else
       {
            [array]$check = $Sys32BinList | where {$_.Name -eq $TargetDirBin.Name}
       }
       
              
       if($check.Length -gt 1)
       {
            foreach($bin in $check)
            {
                [string]$stringpath = $TargetDirBin.FullName
                [string]$checkps2 = @($check| %{$_.FullName})
                if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $bin.FullName -ErrorAction SilentlyContinue
                        $Sys32BinHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $bin.FullName -ErrorAction SilentlyContinue
                        $Sys32BinHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
                    $SusBinListObject = New-Object psobject
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $bin.FullName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $bin.VersionInfo.OriginalFileName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $TargetDirHash.Hash
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32BinHash.Hash
                    $SusBinListArray += $SusBinListObject
                }
            }
       }
       if($check.Length -eq 1)
       {
            [string]$stringpath = $TargetDirBin.FullName
            [string]$checkps2 = @($check| %{$_.FullName})
            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $TargetDirBin.FullName -ErrorAction SilentlyContinue
                        $Sys32BinHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $TargetDirBin.FullName -ErrorAction SilentlyContinue
                        $Sys32BinHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
            $SusBinListObject = New-Object psobject
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $TargetDirBin.FullName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $TargetDirBin.VersionInfo.OriginalFileName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $TargetDirHash.Hash
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32BinHash.Hash
            $SusBinListArray += $SusBinListObject
            }
       }
       
       
    }

    
    

}


$SusBinListArray | Export-csv -NoTypeInformation $CollectionPath\SuspiciousBinsList.csv

# End of PRocess Dump
}

## End Suspicious Bin Audit
## Start Suspicious DLL Audit
Function Get-SusDllsPS45
{
write-host "Scanning for system dlls not in the default locations"
$SusDLLListArray = @()
$ErrorActionPreference = "SilentlyContinue"
$count = 0

#Start Find possible sideloaded DLLs
foreach($TargetDirDll in $TargetDLLs)
{

    if($64DllsOnly.InputObject -contains $TargetDirDll.Name)
    {
      $DllSigResult = Get-AuthenticodeSignature $TargetDirDll.FullName -ErrorAction Ignore
      $CertSubject = Get-AuthenticodeSignature $TargetDirDll.FullName | Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
      $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
      if ($CertSubject.Subject -ne $MSSubject)
      { 
        [array]$check = $Sys64DLLList | where {$_.Name -eq $TargetDirDll.Name}
        if($check.Length -gt 1)
        {
            foreach($bin in $check)
            {
                [string]$stringpath = $TargetDirDll.FullName
                if (($bin.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $stringpath -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-Hash -Algorithm MD5 -FilePath $bin.FullName -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $stringpath -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-FileHash -Algorithm MD5 $bin.FullName -ErrorAction SilentlyContinue
                    }
                    $SusDLLListObject = New-Object psobject
                    $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "SusDll" -Value $stringpath
                    $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "SusDllHash" -Value $TargetDirHash.Hash
                    $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $bin.FullName
                    $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64DllHash.Hash
                    $SusDLLListArray += $SusDLLListObject
                }
            }
       }
        if($check.Length -eq 1)
        {
            [string]$stringpath = $TargetDirDll.FullName
            if (($check.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $TargetDirDll.FullName -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-Hash -Algorithm MD5 -FilePath $check.FullName -ErrorAction SilentlyContinue
                    }
                    else
                    { 
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $TargetDirDll.FullName -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-FileHash -Algorithm MD5 $check.FullName -ErrorAction SilentlyContinue
                    }
            $SusDLLListObject = New-Object psobject
            $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "SusDll" -Value $bin.FullName
            $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "SusDllHash" -Value $TargetDirHash.Hash
            $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $check.FullName
            $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64DllHash.Hash
            $SusDLLListArray += $SusDLLListObject
            }
       }
      }
    }
    elseif ($Sys32DLLList.Name -contains $TargetDirDll.Name)
    {
       $DllSigResult = Get-AuthenticodeSignature $TargetDirDll.FullName -ErrorAction Ignore
       $CertSubject = Get-AuthenticodeSignature $TargetDirDll.FullName | Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
      $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
      if ($CertSubject.Subject -ne $MSSubject)
      {      
        [array]$check = $Sys32DLLList | where {$_.Name -eq $TargetDirDll.Name}
       
        if($check.Length -gt 1)
        {
            foreach($bin in $check)
            {
                [string]$stringpath = $TargetDirDll.FullName
                if (($bin.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    { 
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $stringpath -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-Hash -Algorithm MD5 -FilePath $check.FullName -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $stringpath -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-FileHash -Algorithm MD5 $check.FullName -ErrorAction SilentlyContinue
                    }
                    $SusDLLListObject = New-Object psobject
                    $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "SusDll" -Value $stringpath
                    $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "SusDllHash" -Value $TargetDirHash.Hash
                    $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $bin.FullName
                    $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32DllHash.Hash
                    $SusDLLListArray += $SusDLLListObject
                }
            }
       }
        if($check.Length -eq 1)
        {
            [string]$stringpath = $TargetDirDll.FullName
            if (($check.FullName.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $TargetDirDll.FullName -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-Hash -Algorithm MD5 -FilePath $check.FullName -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $TargetDirDll.FullName -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-FileHash -Algorithm MD5 $check.FullName -ErrorAction SilentlyContinue
                    }
            $SusDLLListObject = New-Object psobject
            $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "SusDll" -Value $TargetDirDll.FullName
            $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "SusDllHash" -Value $TargetDirHash.Hash
            $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $check.FullName
            $SusDLLListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32BinHash.Hash
            $SusDLLListArray += $SusDLLListObject
            }
       }
      }
       
    }

    
    

}


$SusDLLListArray | Export-csv -NoTypeInformation $CollectionPath\SuspiciousDllsList.csv

}

Function Get-SusDllsPS23
{
write-host "Scanning for system dlls not in the default locations"
$SusDllListArray = @()
$ErrorActionPreference = "SilentlyContinue"
$count = 0

#Start Find possible sideloaded Dlls
foreach($TargetDirDll in $TargetDLLs)
{    
    if((@($64DllsOnly | %{$_.InputObject}) -contains $TargetDirDll.Name))
    {
      $DllSigResult = Get-AuthenticodeSignature $TargetDirDll.FullName -ErrorAction Ignore
      $CertSubject = Get-AuthenticodeSignature $TargetDirDll.FullName | ` Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
      $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
      if ($CertSubject.Subject -ne $MSSubject)
      {  
       [array]$check = $Sys64DLLList | where {$_.Name -eq $TargetDirDll.Name}
       
       if($check.Length -gt 1)
       {
            foreach($bin in $check)
            {
                
                [string]$stringpath = $TargetDirDll.FullName
                [string]$checkps2 = @($bin| %{$_.FullName})
                if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $stringpath -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $stringpath -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
                    $SusDllListObject = New-Object psobject
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDll" -Value $stringpath
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDllHash" -Value $TargetDirHash.Hash
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64DllHash.Hash
                    $SusDllListArray += $SusDllListObject
                }
            }
       }
       if($check.Length -eq 1)
       {
            [string]$stringpath = $TargetDirDll.FullName
            [string]$checkps2 = @($check| %{$_.FullName})
            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    { 
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $TargetDirDll.FullName -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $TargetDirBin.FullName -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
            $SusDllListObject = New-Object psobject
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDll" -Value $TargetDirDll.FullName
            
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDllHash" -Value $TargetDirHash.Hash
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64DllHash.Hash
            $SusDllListArray += $SusDllListObject
            }
       }
      }
    }
    elseif (@($Sys32DLLList| %{$_.Name}) -contains $TargetDirDll.Name)
    {
      $DllSigResult = Get-AuthenticodeSignature $TargetDirDll.FullName -ErrorAction Ignore
      $CertSubject = Get-AuthenticodeSignature $TargetDirDll.FullName | ` Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
      $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
      if ($CertSubject.Subject -ne $MSSubject)
      {  
       [array]$check = $Sys32DLLList | where {$_.Name -eq $TargetDirDll.Name}
                    
       if($check.Length -gt 1)
       {
            foreach($bin in $check)
            {
                [string]$stringpath = $TargetDirDll.FullName
                [string]$checkps2 = @($bin | %{$_.FullName})
                if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $bin.FullName -ErrorAction SilentlyContinue
                        $Sys32DllHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $bin.FullName -ErrorAction SilentlyContinue
                        $Sys32DllHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
                    $SusDllListObject = New-Object psobject
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDll" -Value $bin.FullName
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDllHash" -Value $TargetDirHash.Hash
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32DllHash.Hash
                    $SusDllListArray += $SusDllListObject
                }
            }
       }
       if($check.Length -eq 1)
       {
            [string]$stringpath = $TargetDirDll.FullName
            [string]$checkps2 = @($check| %{$_.FullName})
            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $TargetDirHash = Get-Hash -Algorithm MD5 -FilePath $TargetDirDll.FullName -ErrorAction SilentlyContinue
                        $Sys32DllHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $TargetDirHash = Get-FileHash -Algorithm MD5 $TargetDirDll.FullName -ErrorAction SilentlyContinue
                        $Sys32DllHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
            $SusDllListObject = New-Object psobject
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $TargetDirDll.FullName
            
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $TargetDirHash.Hash
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32DllHash.Hash
            $SusDllListArray += $SusDllListObject
            }
       }
      }
       
    }

    
    

}


$SusDLLListArray | Export-csv -NoTypeInformation $CollectionPath\SuspiciousDllsList.csv


}
## End suspicious DLL Audit

## End Suspicious Bin Audit

if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{Write-Output 'Running as Administrator!'}
else
{
    Write-Output 'Rerun Script as Administrator'
    exit 
}

Write-Host "Creating output folder in current working directory"
$CollectionPath =".\" + $ENV:COMPUTERNAME + "_" + (Get-Date).tostring("yyyyMMdd")
New-Item $CollectionPath -Type Directory -Force
$LRInvocation = $MyINvocation.InvocationName



if ($PSVersionTable.PSVersion.Major -lt 4)
{
    $ErrorActionPreference = "SilentlyContinue"
    $Sys32BinList = Get-ChildItem $env:SystemRoot\system32\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue | Select Name, FullName
    $Sys64BinList = Get-ChildItem $env:SystemRoot\syswow64\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue | Select Name, FullName
    $PS2_32Test = @($Sys32BinList | %{$_.Name})
    $PS2_64Test = @($Sys64BinList | %{$_.Name})
    $64BinsOnly = Compare-Object -ReferenceObject $PS2_64Test -DifferenceObject $PS2_32Test  | Where-Object {$_.SideIndicator -eq "<="} | Select InputObject
    $Sys32DLLList = Get-ChildItem $env:SystemRoot\system32\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".dll")} -ErrorAction SilentlyContinue | Select Name, FullName
    $Sys64DLLList = Get-ChildItem $env:SystemRoot\syswow64\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".dll")} -ErrorAction SilentlyContinue | Select Name, FullName
    $PS2_32Dlls = @($Sys32DLLList | %{$_.Name})
    $PS2_64Dlls = @($Sys64DLLList | %{$_.Name})
    $64DllsOnly = Compare-Object -ReferenceObject $PS2_64Dlls -DifferenceObject $PS2_32Dlls  | Where-Object {$_.SideIndicator -eq "<="} | Select InputObject
    Get-SideLoadDetectsPS23
    Get-SusShimCachePS23
    Get-SusExecsPS23
    Get-SusDllsPS23
}
else
{
    $ErrorActionPreference = "SilentlyContinue"
    $Sys32BinList = Get-ChildItem $env:SystemRoot\system32\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue | Select Name, FullName
    $Sys64BinList = Get-ChildItem $env:SystemRoot\syswow64\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue | Select Name, FullName
    $64BinsOnly = Compare-Object -ReferenceObject $Sys64BinList.Name -DifferenceObject $Sys32BinList.Name | Where-Object SideIndicator -eq '<=' | Select InputObject
    $Sys32DLLList = Get-ChildItem $env:SystemRoot\system32\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".dll")} -ErrorAction SilentlyContinue | Select Name, FullName
    $Sys64DLLList = Get-ChildItem $env:SystemRoot\syswow64\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".dll")} -ErrorAction SilentlyContinue | Select Name, FullName
    $64DllsOnly = Compare-Object -ReferenceObject $Sys64DLLList.Name -DifferenceObject $Sys32DLLList.Name | Where-Object SideIndicator -eq '<=' | Select InputObject
    Get-SideLoadDetectsPS45
    Get-SusShimCachePS45
    Get-SusExecsPS45
    Get-SusDllsPS45
}
