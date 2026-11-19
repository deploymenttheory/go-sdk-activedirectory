# Functions only: validate one explicitly selected private ordinary-account fixture.
function Read-Sdk07OrdinaryActor {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$ServerVersion,[Parameter(Mandatory)][string]$ProfileId)
    if($ServerVersion-cnotin@('2016','2019','2022','2025')-or$RunId-cnotmatch'\Asdk07-p(16|19|22|25)-[a-z0-9-]{10,25}\z'-or-not$RunId.StartsWith(('sdk07-p'+$ServerVersion.Substring(2)+'-'),[StringComparison]::Ordinal)){throw 'Ordinary actor run/profile differs.'}
    $capture=Join-Path 'H:\ad-sdk-lab\portable-kerberos' $RunId
    $ownerPath=Join-Path $capture 'sdk07-ordinary-owner.json'
    $preparedPath=Join-Path $capture 'prepare.json'
    $secretPath=Join-Path $capture 'secrets\client.clixml'
    foreach($path in @($ownerPath,$preparedPath,$secretPath)){
        for($cursor=$path;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)){
            $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Ordinary actor path cannot traverse a reparse point.'}
        }
    }
    $owner=Get-Content -LiteralPath $ownerPath -Raw|ConvertFrom-Json
    $prepared=Get-Content -LiteralPath $preparedPath -Raw|ConvertFrom-Json
    if($owner.purpose-cne'sdk07-ordinary-rpc-refusal'-or$owner.phase-cne'ready'-or$owner.run_id-cne$RunId-or$owner.profile_id-cne$ProfileId-or$owner.server_version-cne$ServerVersion-or$owner.actor.policy_applied){throw 'Ordinary actor owner is not ready for this profile.'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($RunId))}finally{$sha.Dispose()}
    $username='sdkkrb'+([BitConverter]::ToString($digest).Replace('-','').ToLowerInvariant()).Substring(0,12)
    $principal=$username+'@AD.SDK.TEST'
    if($owner.actor.run_id-cne$RunId-or$owner.actor.principal-cne$principal-or$owner.actor.credential_file-cne$secretPath-or$prepared.run_id-cne$RunId-or$prepared.client_guid-cne$owner.client_guid-or$prepared.parent_guid-cne$owner.parent_guid-or$prepared.upn-cne$principal-or$prepared.sam-cne$username-or$prepared.phase-cne'ready'-or$prepared.policy_applied){throw 'Ordinary actor prepared identity differs.'}
    $null=[guid]::Parse($owner.client_guid);$null=[guid]::Parse($owner.parent_guid)
    $membership=$owner.membership
    if(-not$membership.ordinary-or$membership.client_guid-cne$owner.client_guid-or$membership.primary_group-ne513-or@($membership.member_of).Count-ne0-or$membership.account_group_changes-ne0){throw 'Ordinary account membership is not proven.'}
    if($membership.sid-cnotmatch'\AS-1-5-21-\d+-\d+-\d+-\d+\z'){throw 'Ordinary account SID differs.'}
    $domainSid=$membership.sid.Substring(0,$membership.sid.LastIndexOf('-'))
    # These reference-token identities are not an administrative membership grant.
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
    $allowedGroups=@(($domainSid+'-513'),'S-1-5-32-545','S-1-5-32-554','S-1-1-0','S-1-5-11','S-1-5-15','S-1-18-2','S-1-16-8192')
    if(@($membership.authorization_groups).Count-eq0-or@($membership.authorization_groups|Where-Object {$_-cnotin$allowedGroups}).Count-ne0){throw 'Ordinary account authorization groups differ.'}
    if((Get-FileHash -LiteralPath $secretPath -Algorithm SHA256).Hash.ToLowerInvariant()-cne$owner.credential_sha256){throw 'Private ordinary actor credential differs.'}
    $credential=Import-Clixml -LiteralPath $secretPath
    if($credential-isnot[PSCredential]-or$credential.UserName-cne$principal){throw 'Private ordinary actor principal differs.'}
    [pscustomobject]@{credential=$credential;username=$username;principal=$principal;run_id=$RunId;client_guid=$owner.client_guid;parent_guid=$owner.parent_guid;ordinary=$true}
}
