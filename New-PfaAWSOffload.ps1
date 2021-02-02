function New-PfaAwsOffloadConnection {
    <#
    .SYNOPSIS
      Configures an AWS S3 Offload Connection on a FlashArray or CBS target.
    .DESCRIPTION
      Creates a new S3 bucket, enables encryption, creates an IAM user group called PureStorage_Offload_Users if not already there, creates a new user, assigns it a policy only to interact with the new S3 bucket, adds it to the group, adds the Offload target to the specified FlashArray.
    .INPUTS
      AWS credentials, FlashArray credentials, AWS region
    .OUTPUTS
      Returns Offload connection information.
    .EXAMPLE
      PS C:\ New-PfaAwsOffloadConnection

      Default names and behavior creating all objects from scratch. Will ask for authentication interactively.
    .EXAMPLE
      PS C:\ New-PfaAwsOffloadConnection -AwsRegion us-east-1 -FlashArray flasharray-x50-1.purecloud.com -FlashArrayCredential (get-credential) -IgnoreCertificateError -AwsCredential (get-credential) -AwsBucketName codytest-pure

      Creates an S3 bucket in us-east-1 (or uses it if already in existence) called codytest-pure and configures offload on the FlashArray flasharray-x50-1.purecloud.com

    .NOTES
      Version:        1.0
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  01/02/2021
      Purpose/Change: First version
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='AppID')]
    Param(
            [Parameter(Position=0,ParameterSetName="NewUser")]
            [string]$OffloadIamGroupName = "PureStorage_Offload_Users",

            [Parameter(Position=1,ParameterSetName="NewUser")]
            [string]$OffloadIamUserName,
            
            [Parameter(Position=2)]
            [string]$AwsBucketName,

            [Parameter(Position=3,mandatory=$True)]
            [string]$AwsRegion,

            [Parameter(Position=4,mandatory=$True)]
            [string]$FlashArray,

            [Parameter(Position=5,mandatory=$true)]
            [System.Management.Automation.PSCredential]$FlashArrayCredential,

            [Parameter(Position=6,ParameterSetName="ExistingUser")]
            [System.Management.Automation.PSCredential]$OffloadAwsCredential,

            [Parameter(Position=7)]
            [System.Management.Automation.PSCredential]$AwsCredential,

            [Parameter(Position=8)]
            [Switch]$IgnoreCertificateError

    )
  $ErrorActionPreference = "stop"
  $AwsModules = Get-Module AWS.Tools.* -ListAvailable 
  $RequiredModules = @("AWS.Tools.S3","AWS.Tools.Common","AWS.Tools.IdentityManagement")
  $notFoundModules = compare-object $AwsModules $RequiredModules |Where-Object {$_.SideIndicator -eq "=>"}
  if ($notFoundModule.count -ne 0)
  {
    $InstallerModule = Get-Module AWS.Tools.Installer -ListAvailable 
    if ($null -eq $InstallerModule)
    {
      Install-Module -Name AWS.Tools.Installer -Confirm:$false -ErrorAction Stop
    }
    foreach ($notFoundModule in $notFoundModules) 
    {
      Install-AWSToolsModule $notFoundModule.InputObject -CleanUp -Confirm:$false -ErrorAction Stop
    }
  }
  try {
    $fa = New-PfaConnection -Endpoint $FlashArray -Credentials $FlashArrayCredential -IgnoreCertificateError:$IgnoreCertificateError -DefaultArray -ErrorAction Stop
  }
  catch {
      if ($_.exception.message -like "*SSL*")
      {
        $title   = 'FlashArray SSL Certificate Error'
        $msg     = 'Do you want to ignore this certificate error for the FlashArray? (You can use -IgnoreCertificateError to automatically ignore)'
        $options = '&Yes', '&No'
        $default = 1  
        $response = $Host.UI.PromptForChoice($title, $msg, $options, $default)
        if ($response -eq 0) {
            $fa = New-PfaConnection -Endpoint $FlashArray -Credentials $FlashArrayCredential -IgnoreCertificateError -DefaultArray -ErrorAction Stop
        }
        else {
            $fa = New-PfaConnection -Endpoint $FlashArray -Credentials $FlashArrayCredential -DefaultArray -ErrorAction Stop
        }
      }
  }
  if ($null -ne $AwsCredential)
  {
    $AwsSecretKey = ConvertFrom-SecureString $AwsCredential.Password -AsPlainText 
    Set-AWSCredential `
                  -AccessKey $AwsCredential.UserName `
                  -SecretKey $AwsSecretKey `
                  -StoreAs offloadtemp
  }
  else {
    $foundCreds = Get-AWSCredential -ProfileName default
    if ($null -eq $foundCreds)
    {
      if ($null -eq $AwsCredential)
      {
        $AwsCredential = Get-Credential -Title "AWS Credentials" -Message "Please enter your AWS access key (user name) and secret key (password) to authenticate this script to AWS" 
      }
      $AwsSecretKey = ConvertFrom-SecureString $AwsCredential.Password -AsPlainText 
      Set-AWSCredential `
                    -AccessKey $AwsCredential.UserName `
                    -SecretKey $AwsSecretKey `
                    -StoreAs offloadtemp
    }
    else {
      Set-AWSCredential `
                    -AccessKey ($foundCreds.GetCredentials()).AccessKey `
                    -SecretKey ($foundCreds.GetCredentials()).SecretKey `
                    -StoreAs offloadtemp
    }
  }
  $Regions = Get-AWSRegion -IncludeGovCloud -IncludeChina 
  do {
    if ([string]::IsNullOrWhiteSpace($AwsRegion))
    {
      $AwsRegion = Read-Host -Prompt "Please enter an AWS region (ex. eu-north-1)"
    }
    $RegionNotFound = $True
    $RegionNotFound = ($Regions.Region -notcontains $AwsRegion)
    if ($RegionNotFound)
    {
      Write-Warning -Message "Invalid region specifed $($AwsRegion), please re-enter region."
      $AwsRegion = $null
    }
  } while ($RegionNotFound)
  $bucketGuid = (new-guid).Guid
  if ([string]::IsNullOrWhiteSpace($AwsBucketName))
  {
    $AwsBucketName = "purestorage-offload-$($bucketGuid)"
  }
  if ($null -eq $OffloadAwsCredential)
  {
    if ([string]::IsNullOrWhiteSpace($OffloadIamUserName))
    {
      $OffloadIamUserName = "purestorage-offload-$($bucketGuid)"
    }
    $ErrorActionPreference = "SilentlyContinue"
    $OffloadIamGroup = Get-IamGroup -GroupName $OffloadIamGroupName -ProfileName offloadtemp -Region $AwsRegion
    $ErrorActionPreference = "stop"
    if ($null -eq $OffloadIamGroup)
    {
      Write-Host "Creating IAM group $($OffloadIamGroupName)"
      $OffloadIamGroup = New-IamGroup -Groupname $OffloadIamGroupName -ProfileName offloadtemp -ErrorAction Stop -Region $AwsRegion
      Write-debug $OffloadIamGroupName
    }
    $ErrorActionPreference = "SilentlyContinue"
    $OffloadIamUser = Get-IAMUser -Username $OffloadIamUserName -ProfileName offloadtemp 
    $ErrorActionPreference = "stop"
    if ($null -eq $OffloadIamUser)
    {
      Write-Host "Creating IAM user $($OffloadIamUserName)"
      $OffloadIamUser = New-IAMUser -Username $OffloadIamUserName -ProfileName offloadtemp -ErrorAction Stop -Region $AwsRegion
      Write-debug $OffloadIamUserName
      Add-IAMUserToGroup -UserName $OffloadIamUserName -GroupName $OffloadIamGroupName -ProfileName offloadtemp -ErrorAction Stop -Region $AwsRegion
      $UserCreated = $true
    }
  }
  $AwsBucket = Get-S3Bucket -BucketName $AwsBucketName -ProfileName offloadtemp -ErrorAction SilentlyContinue -Region $AwsRegion
  if ($null -eq $AwsBucket)
  {
    Write-debug $AwsBucketName
    Write-Host "Creating S3 Bucket $($AwsBucketName)"
    $bucket = New-S3Bucket -BucketName $AwsBucketName -Region $AwsRegion -ProfileName offloadtemp -ErrorAction Stop
    $BucketCreated = $true
    $initializeBucket = $True
  }
  else 
  {
    $mountObject = Get-S3Object -BucketName $AwsBucketName -Key mount_desc -ProfileName offloadtemp -Region $AwsRegion
    if ($null -eq $mountObject)
    {
      $objects = Get-S3Object -BucketName $AwsBucketName -ProfileName offloadtemp -Region $AwsRegion
      if ($objects.count -gt 0)
      {
        if ($UserCreated -eq $true)
        {
          Write-Host "Deleting user $($OffloadIamUserName)"
          Remove-IAMUserFromGroup -GroupName $OffloadIamGroupName -UserName $OffloadIamUserName -ProfileName offloadtemp -Confirm:$false -Region $AwsRegion |Out-Null
          Remove-IAMUser -UserName $OffloadIamUserName -ProfileName offloadtemp -Confirm:$false -Region $AwsRegion |Out-Null
        }
        throw "This bucket is in use for something other than offload. It must be an empty bucket or configured for exclusive use of offload snapshots."
      }
      else {
        $initializeBucket = $True
      }
    }
    else {
      $initializeBucket = $false
    }
  }
  if ($initializeBucket -eq $true)
  {
    $Encryptionconfig = @{ServerSideEncryptionByDefault = @{ServerSideEncryptionAlgorithm = "AES256"}}
    Set-S3BucketEncryption -BucketName $AwsBucketName -ServerSideEncryptionConfiguration_ServerSideEncryptionRule $Encryptionconfig -ProfileName offloadtemp -Region $AwsRegion
  }
  if ($UserCreated -eq $true)
  {
$policyDoc = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect":  "Allow",
        "Action":  ["s3:ListAllMyBuckets", "s3:GetBucketLocation"],
        "Resource":  ["*"]
        },
        {
        "Effect":  "Allow",
        "Action":  ["*"],
        "Resource":  ["arn:aws:s3:::$($AwsBucketName)"]
        },
        {
        "Effect":  "Allow",
        "Action":  ["s3:*Object"],
        "Resource":  ["arn:aws:s3:::$($AwsBucketName)/*"]
        }
    ]
}
"@
    Write-Debug $policyDoc
    Write-IAMUserPolicy -UserName $OffloadIamUserName -ProfileName offloadtemp -PolicyName "pureoffload-$($OffloadIamUserName)-$(get-date -f yyyyMMddHHmmss)" -PolicyDocument $policyDoc -Region $AwsRegion
  }
  if ($null -eq $OffloadAwsCredential)
  {
    $NewApiKey = New-IAMAccessKey -UserName $OffloadIamUserName -ProfileName offloadtemp -Region $AwsRegion
    $secpasswd = ConvertTo-SecureString $NewApiKey.SecretAccessKey -AsPlainText -Force
    $OffloadAwsCredential = New-Object System.Management.Automation.PSCredential ($NewApiKey.AccessKeyId, $secpasswd)
  }
  do {
    $ErrorActionPreference = "SilentlyContinue"
    $credentialCheck = Get-S3Bucket -BucketName $AwsBucketName -Region $AwsRegion -AccessKey $OffloadAwsCredential.UserName -SecretKey (ConvertFrom-SecureString -SecureString $OffloadAwsCredential.Password -AsPlainText)
    $ErrorActionPreference = "Stop"
    Start-Sleep -Seconds 2
   } while ($null -eq $credentialCheck)    
  try {
    $faSession = New-PfaRestSession -Flasharray $fa
    $OffloadRequest = [ordered]@{
     access_key_id = $OffloadAwsCredential.UserName
     bucket = $AwsBucketName
     initialize = $initializeBucket
     secret_access_key = (ConvertFrom-SecureString -SecureString $OffloadAwsCredential.Password -AsPlainText)
     } | ConvertTo-Json
     Write-Debug $OffloadRequest
     Write-Host "Adding Offload Target to FlashArray $($fa.Endpoint)"
    $offload = New-PfaRestOperation -PfaSession $faSession -RestOperationType POST -ResourceType "s3_offload/$($AwsBucketName)" -JsonBody $OffloadRequest -Url $fa.Endpoint -SkipCertificateCheck:$IgnoreCertificateError 
    Remove-AWSCredentialProfile -ProfileName offloadtemp -Confirm:$false |Out-Null
    return $offload
 }
 catch {
   if ($UserCreated -eq $true)
   {
     $policy = Get-IAMUserPolicies -UserName $OffloadIamUserName -ProfileName offloadtemp -Region $AwsRegion
     Write-Host "Deleting user $($OffloadIamUserName)"
     Remove-IAMUserPolicy -PolicyName $policy -UserName $OffloadIamUserName -Confirm:$false -ProfileName offloadtemp -Region $AwsRegion
     Remove-IAMUserFromGroup -GroupName $OffloadIamGroupName -UserName $OffloadIamUserName -ProfileName offloadtemp -Confirm:$false -Region $AwsRegion |Out-Null
     Remove-IAMAccessKey -AccessKeyId $NewApiKey.AccessKeyId -UserName $OffloadIamUserName -ProfileName offloadtemp -Confirm:$false -Region $AwsRegion |Out-Null
     Remove-IAMUser -UserName $OffloadIamUserName -ProfileName offloadtemp -Confirm:$false -Region $AwsRegion |Out-Null
   }
   if ($bucketCreated -eq $true)
   {
     Write-Host "Deleting bucket $($AwsBucketName)"
     Remove-S3Bucket -BucketName $AwsBucketName -ProfileName offloadtemp -Confirm:$false -Region $AwsRegion |Out-Null
   }
   Remove-AWSCredentialProfile -ProfileName offloadtemp -Confirm:$false |Out-Null
   throw $_.ErrorDetails
 }
}

