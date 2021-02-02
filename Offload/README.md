
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
