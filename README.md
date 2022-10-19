# sysmon-parser
Automatically generated Sysmon parser for Azure Sentinel

Sysmon-AllVersions_Parser.txt can be loaded as a function in Azure Sentinel to parse all your events.
There is an Azure Devops pipeline that triggers daily to install the latest Sysmon version, extracts the schema and populates the parser with all unique fields.
