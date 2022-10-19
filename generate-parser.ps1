[xml]$schema = Sysmon.exe -nologo -s
$sysmonColumnList = @()
$sysmonColumnList= $schema.manifest.events.event.data | select name -Unique | foreach {$_.name}
$nativeColumnList = @("TimeGenerated", "Source", "EventLog", "Computer", "EventLevel", "EventLevelName", "EventID", "UserName", "RenderedDescription", "MG", "ManagementGroupName", "_ResourceId")
$querybase = @'
Event
| where Source == "Microsoft-Windows-Sysmon"
| extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])
| extend EventData = parse_xml(EventData).DataItem.EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key = tostring(column_ifexists('@Name', "")), Value = tostring(column_ifexists('#text', ""))
| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, _ResourceId)
'@
$extend = @'

| extend 
'@
$columnList = $nativeColumnList + $sysmonColumnList
foreach ($colum in $columnList)
{
    $extend += $colum + " = column_ifexists(`"$($colum)`", `"`"), "
}
$extend = $extend.substring(0, $extend.Length - 2)
$tail = @'

// Fix for wrong casing in EventID10
| extend SourceProcessGuid=iff(isnotempty(SourceProcessGUID),SourceProcessGUID,SourceProcessGuid), TargetProcessGuid=iff(isnotempty(TargetProcessGUID),TargetProcessGUID,TargetProcessGuid)
| project-away SourceProcessGUID, TargetProcessGUID  
// end fix
| parse RuleName with * 'technique_id=' TechniqueId ',' * 'technique_name=' TechniqueName
| parse Hashes with * 'SHA1=' SHA1 ',' * 'MD5=' MD5 ',' * 'SHA256=' SHA256 ',' * 'IMPHASH=' IMPHASH 
'@
$parser = $querybase + $extend + $tail
$parser | Out-File Sysmon-AllVersions_Parser.txt
