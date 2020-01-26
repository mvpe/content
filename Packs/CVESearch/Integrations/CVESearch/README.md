## Overview
---

Search CVE Information - powered by circl.lu
This integration was integrated and tested with CVE Search

## Use Cases
---

## Configure CVE Search on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for CVESearch_V2.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL__
4. Click __Test__ to validate the URLs and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. cve-search
2. cve-latest
3. cve
### 1. cve-search
---
Search CVE by ID

##### Base Command

`cve-search`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | A comma separated list of CVE IDs to search. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. | 
| CVE.CVSS | String | The CVSS score of the CVE. | 
| CVE.Published | Date | The date the CVE was published. | 
| CVE.Modified | Date | The date the CVE was last modified. | 
| CVE.Description | String | The description of the CVE. | 


##### Command Example
```!cve-search cve_id=CVE-2014-1234```

##### Context Example
```
{
    "CVE": [
        {
            "ID": "CVE-2014-1234", 
            "Published": "2014-01-10T12:02:00", 
            "CVSS": 2.1, 
            "Modified": "2014-01-10T17:57:00", 
            "Description": "The paratrooper-newrelic gem 1.0.1 for Ruby allows local users to obtain the X-Api-Key value by listing the curl process."
        }
    ]
}
```

##### Human Readable Output
Integration log: {'CVE(val.ID === obj.ID)': [{'ID': 'CVE-2014-1234', 'CVSS': 2.1, 'Published': '2014-01-10T12:02:00', 'Modified': '2014-01-10T17:57:00', 'Description': 'The paratrooper-newrelic gem 1.0.1 for Ruby allows local users to obtain the X-Api-Key value by listing the curl process.'}]}
### CVE Search results
|CVSS|Description|ID|Modified|Published|
|---|---|---|---|---|
| 2.1 | The paratrooper-newrelic gem 1.0.1 for Ruby allows local users to obtain the X-Api-Key value by listing the curl process. | CVE-2014-1234 | 2014-01-10T17:57:00 | 2014-01-10T12:02:00 |


### 2. cve-latest
---
Retruns the latest updated CVEs.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`cve-latest`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. | 
| CVE.CVSS | String | The CVSS score of the CVE. | 
| CVE.Published | Date | The date the CVE was published. | 
| CVE.Modified | Date | When CVE was last modified. | 
| CVE.Description | String | The description of the CVE. | 


##### Command Example
```!cve-latest```

##### Context Example
```
{
    "CVE": [
        {
            "ID": "CVE-2020-7998", 
            "Published": "2020-01-28T05:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T05:15:00", 
            "Description": "An arbitrary file upload vulnerability has been discovered in the Super File Explorer app 1.0.1 for iOS. The vulnerability is located in the developer path that is accessible and hidden next to the root path. By default, there is no password set for the FTP or Web UI service."
        }, 
        {
            "ID": "CVE-2020-7997", 
            "Published": "2020-01-28T05:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T05:15:00", 
            "Description": "ASUS WRT-AC66U 3 RT 3.0.0.4.372_67 devices allow XSS via the Client Name field to the Parental Control feature."
        }, 
        {
            "ID": "CVE-2019-5474", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An authorization issue was discovered in GitLab EE < 12.1.2, < 12.0.4, and < 11.11.6 allowing the merge request approval rules to be overridden without appropriate permissions."
        }, 
        {
            "ID": "CVE-2019-5472", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An authorization issue was discovered in Gitlab versions < 12.1.2, < 12.0.4, and < 11.11.6 that prevented owners and maintainer to delete epic comments."
        }, 
        {
            "ID": "CVE-2019-5470", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An information disclosure issue was discovered GitLab versions < 12.1.2, < 12.0.4, and < 11.11.6 in the security dashboard which could result in disclosure of vulnerability feedback information."
        }, 
        {
            "ID": "CVE-2019-5468", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An privilege escalation issue was discovered in Gitlab versions < 12.1.2, < 12.0.4, and < 11.11.6 when Mattermost slash commands are used with a blocked account."
        }, 
        {
            "ID": "CVE-2019-5466", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An IDOR was discovered in GitLab CE/EE 11.5 and later that allowed new merge requests endpoint to disclose label names."
        }, 
        {
            "ID": "CVE-2019-5465", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An information disclosure issue was discovered in GitLab CE/EE 8.14 and later, by using the move issue feature which could result in disclosure of the newly created issue ID."
        }, 
        {
            "ID": "CVE-2019-5464", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "A flawed DNS rebinding protection issue was discovered in GitLab CE/EE 10.2 and later in the `url_blocker.rb` which could result in SSRF where the library is utilized."
        }, 
        {
            "ID": "CVE-2019-5462", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "A privilege escalation issue was discovered in GitLab CE/EE 9.0 and later when trigger tokens are not rotated once ownership of them has changed."
        }, 
        {
            "ID": "CVE-2019-15607", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "A stored XSS vulnerability is present within node-red (version: <= 0.20.7) npm package, which is a visual tool for wiring the Internet of Things. This issue will allow the attacker to steal session cookies, deface web applications, etc."
        }, 
        {
            "ID": "CVE-2019-15590", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An access control issue exists in < 12.3.5, < 12.2.8, and < 12.1.14 for GitLab Community Edition (CE) and Enterprise Edition (EE) where private merge requests and issues would be disclosed with the Group Search feature provided by Elasticsearch integration"
        }, 
        {
            "ID": "CVE-2019-15586", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "A XSS exists in Gitlab CE/EE < 12.1.10 in the Mermaid plugin."
        }, 
        {
            "ID": "CVE-2019-15585", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "Improper authentication exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) in the GitLab SAML integration had a validation issue that permitted an attacker to takeover another user's account."
        }, 
        {
            "ID": "CVE-2019-15583", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An information disclosure exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE). When an issue was moved to a public project from a private one, the associated private labels and the private project namespace would be disclosed through the GitLab API."
        }, 
        {
            "ID": "CVE-2019-15582", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An IDOR was discovered in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) that allowed a maintainer to add any private group to a protected environment."
        }, 
        {
            "ID": "CVE-2019-15581", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An IDOR exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) that allowed a project owner or maintainer to see the members of any private group via merge request approval rules."
        }, 
        {
            "ID": "CVE-2019-15579", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An information disclosure exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) where the assignee(s) of a confidential issue in a private project would be disclosed to a guest via milestones."
        }, 
        {
            "ID": "CVE-2019-15578", 
            "Published": "2020-01-28T03:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T03:15:00", 
            "Description": "An information disclosure exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE). The path of a private project, that used to be public, would be disclosed in the unsubscribe email link of issues and merge requests."
        }, 
        {
            "ID": "CVE-2020-1933", 
            "Published": "2020-01-28T01:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T01:52:00", 
            "Description": "A XSS vulnerability was found in Apache NiFi 1.0.0 to 1.10.0. Malicious scripts could be injected to the UI through action by an unaware authenticated user in Firefox. Did not appear to occur in other browsers."
        }, 
        {
            "ID": "CVE-2020-1932", 
            "Published": "2020-01-28T01:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T01:52:00", 
            "Description": "An information disclosure issue was found in Apache Superset 0.34.0, 0.34.1, 0.35.0, and 0.35.1. Authenticated Apache Superset users are able to retrieve other users' information, including hashed passwords, by accessing an unused and undocumented API endpoint on Apache Superset."
        }, 
        {
            "ID": "CVE-2020-1928", 
            "Published": "2020-01-28T01:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T01:52:00", 
            "Description": "An information disclosure vulnerability was found in Apache NiFi 1.10.0. The sensitive parameter parser would log parsed values for debugging purposes. This would expose literal values entered in a sensitive property when no parameter was present."
        }, 
        {
            "ID": "CVE-2020-0549", 
            "Published": "2020-01-28T01:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T01:52:00", 
            "Description": "Cleanup errors in some data cache evictions for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access."
        }, 
        {
            "ID": "CVE-2020-0548", 
            "Published": "2020-01-28T01:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T01:52:00", 
            "Description": "Cleanup errors in some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access."
        }, 
        {
            "ID": "CVE-2019-20439", 
            "Published": "2020-01-28T01:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T01:52:00", 
            "Description": "An issue was discovered in WSO2 API Manager 2.6.0. A potential Reflected Cross-Site Scripting (XSS) vulnerability has been identified in defining a scope in the \"manage the API\" page of the API Publisher."
        }, 
        {
            "ID": "CVE-2019-20438", 
            "Published": "2020-01-28T01:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T01:52:00", 
            "Description": "An issue was discovered in WSO2 API Manager 2.6.0. A potential stored Cross-Site Scripting (XSS) vulnerability has been identified in the inline API documentation editor page of the API Publisher."
        }, 
        {
            "ID": "CVE-2019-20437", 
            "Published": "2020-01-28T01:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T01:52:00", 
            "Description": "An issue was discovered in WSO2 API Manager 2.6.0, WSO2 IS as Key Manager 5.7.0, and WSO2 Identity Server 5.8.0. When a custom claim dialect with an XSS payload is configured in the identity provider basic claim configuration, that payload gets executed, if a user picks up that dialect's URI as the provisioning claim in the advanced claim configuration of the same Identity Provider. The attacker also needs to have privileges to log in to the management console, and to add and update identity provider configurations."
        }, 
        {
            "ID": "CVE-2019-20436", 
            "Published": "2020-01-28T01:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T01:52:00", 
            "Description": "An issue was discovered in WSO2 API Manager 2.6.0, WSO2 IS as Key Manager 5.7.0, and WSO2 Identity Server 5.8.0. If there is a claim dialect configured with an XSS payload in the dialect URI, and a user picks up this dialect's URI and adds it as the service provider claim dialect while configuring the service provider, that payload gets executed. The attacker also needs to have privileges to log in to the management console, and to add and configure claim dialects."
        }, 
        {
            "ID": "CVE-2019-20435", 
            "Published": "2020-01-28T01:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T01:52:00", 
            "Description": "An issue was discovered in WSO2 API Manager 2.6.0. A reflected XSS attack could be performed in the inline API documentation editor page of the API Publisher by sending an HTTP GET request with a harmful docName request parameter."
        }, 
        {
            "ID": "CVE-2019-20434", 
            "Published": "2020-01-28T01:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T01:52:00", 
            "Description": "An issue was discovered in WSO2 API Manager 2.6.0. A potential Reflected Cross-Site Scripting (XSS) vulnerability has been identified in the Datasource creation page of the Management Console."
        }
    ]
}
```

##### Human Readable Output
Integration log: {'CVE(val.ID === obj.ID)': [{'ID': 'CVE-2020-7998', 'CVSS': 5.0, 'Published': '2020-01-28T05:15:00', 'Modified': '2020-01-28T05:15:00', 'Description': 'An arbitrary file upload vulnerability has been discovered in the Super File Explorer app 1.0.1 for iOS. The vulnerability is located in the developer path that is accessible and hidden next to the root path. By default, there is no password set for the FTP or Web UI service.'}, {'ID': 'CVE-2020-7997', 'CVSS': 5.0, 'Published': '2020-01-28T05:15:00', 'Modified': '2020-01-28T05:15:00', 'Description': 'ASUS WRT-AC66U 3 RT 3.0.0.4.372_67 devices allow XSS via the Client Name field to the Parental Control feature.'}, {'ID': 'CVE-2019-5474', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An authorization issue was discovered in GitLab EE < 12.1.2, < 12.0.4, and < 11.11.6 allowing the merge request approval rules to be overridden without appropriate permissions.'}, {'ID': 'CVE-2019-5472', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An authorization issue was discovered in Gitlab versions < 12.1.2, < 12.0.4, and < 11.11.6 that prevented owners and maintainer to delete epic comments.'}, {'ID': 'CVE-2019-5470', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An information disclosure issue was discovered GitLab versions < 12.1.2, < 12.0.4, and < 11.11.6 in the security dashboard which could result in disclosure of vulnerability feedback information.'}, {'ID': 'CVE-2019-5468', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An privilege escalation issue was discovered in Gitlab versions < 12.1.2, < 12.0.4, and < 11.11.6 when Mattermost slash commands are used with a blocked account.'}, {'ID': 'CVE-2019-5466', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An IDOR was discovered in GitLab CE/EE 11.5 and later that allowed new merge requests endpoint to disclose label names.'}, {'ID': 'CVE-2019-5465', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An information disclosure issue was discovered in GitLab CE/EE 8.14 and later, by using the move issue feature which could result in disclosure of the newly created issue ID.'}, {'ID': 'CVE-2019-5464', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'A flawed DNS rebinding protection issue was discovered in GitLab CE/EE 10.2 and later in the `url_blocker.rb` which could result in SSRF where the library is utilized.'}, {'ID': 'CVE-2019-5462', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'A privilege escalation issue was discovered in GitLab CE/EE 9.0 and later when trigger tokens are not rotated once ownership of them has changed.'}, {'ID': 'CVE-2019-15607', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'A stored XSS vulnerability is present within node-red (version: <= 0.20.7) npm package, which is a visual tool for wiring the Internet of Things. This issue will allow the attacker to steal session cookies, deface web applications, etc.'}, {'ID': 'CVE-2019-15590', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An access control issue exists in < 12.3.5, < 12.2.8, and < 12.1.14 for GitLab Community Edition (CE) and Enterprise Edition (EE) where private merge requests and issues would be disclosed with the Group Search feature provided by Elasticsearch integration'}, {'ID': 'CVE-2019-15586', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'A XSS exists in Gitlab CE/EE < 12.1.10 in the Mermaid plugin.'}, {'ID': 'CVE-2019-15585', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': "Improper authentication exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) in the GitLab SAML integration had a validation issue that permitted an attacker to takeover another user's account."}, {'ID': 'CVE-2019-15583', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An information disclosure exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE). When an issue was moved to a public project from a private one, the associated private labels and the private project namespace would be disclosed through the GitLab API.'}, {'ID': 'CVE-2019-15582', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An IDOR was discovered in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) that allowed a maintainer to add any private group to a protected environment.'}, {'ID': 'CVE-2019-15581', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An IDOR exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) that allowed a project owner or maintainer to see the members of any private group via merge request approval rules.'}, {'ID': 'CVE-2019-15579', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An information disclosure exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) where the assignee(s) of a confidential issue in a private project would be disclosed to a guest via milestones.'}, {'ID': 'CVE-2019-15578', 'CVSS': 5.0, 'Published': '2020-01-28T03:15:00', 'Modified': '2020-01-28T03:15:00', 'Description': 'An information disclosure exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE). The path of a private project, that used to be public, would be disclosed in the unsubscribe email link of issues and merge requests.'}, {'ID': 'CVE-2020-1933', 'CVSS': 5.0, 'Published': '2020-01-28T01:15:00', 'Modified': '2020-01-28T01:52:00', 'Description': 'A XSS vulnerability was found in Apache NiFi 1.0.0 to 1.10.0. Malicious scripts could be injected to the UI through action by an unaware authenticated user in Firefox. Did not appear to occur in other browsers.'}, {'ID': 'CVE-2020-1932', 'CVSS': 5.0, 'Published': '2020-01-28T01:15:00', 'Modified': '2020-01-28T01:52:00', 'Description': "An information disclosure issue was found in Apache Superset 0.34.0, 0.34.1, 0.35.0, and 0.35.1. Authenticated Apache Superset users are able to retrieve other users' information, including hashed passwords, by accessing an unused and undocumented API endpoint on Apache Superset."}, {'ID': 'CVE-2020-1928', 'CVSS': 5.0, 'Published': '2020-01-28T01:15:00', 'Modified': '2020-01-28T01:52:00', 'Description': 'An information disclosure vulnerability was found in Apache NiFi 1.10.0. The sensitive parameter parser would log parsed values for debugging purposes. This would expose literal values entered in a sensitive property when no parameter was present.'}, {'ID': 'CVE-2020-0549', 'CVSS': 5.0, 'Published': '2020-01-28T01:15:00', 'Modified': '2020-01-28T01:52:00', 'Description': 'Cleanup errors in some data cache evictions for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.'}, {'ID': 'CVE-2020-0548', 'CVSS': 5.0, 'Published': '2020-01-28T01:15:00', 'Modified': '2020-01-28T01:52:00', 'Description': 'Cleanup errors in some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.'}, {'ID': 'CVE-2019-20439', 'CVSS': 5.0, 'Published': '2020-01-28T01:15:00', 'Modified': '2020-01-28T01:52:00', 'Description': 'An issue was discovered in WSO2 API Manager 2.6.0. A potential Reflected Cross-Site Scripting (XSS) vulnerability has been identified in defining a scope in the "manage the API" page of the API Publisher.'}, {'ID': 'CVE-2019-20438', 'CVSS': 5.0, 'Published': '2020-01-28T01:15:00', 'Modified': '2020-01-28T01:52:00', 'Description': 'An issue was discovered in WSO2 API Manager 2.6.0. A potential stored Cross-Site Scripting (XSS) vulnerability has been identified in the inline API documentation editor page of the API Publisher.'}, {'ID': 'CVE-2019-20437', 'CVSS': 5.0, 'Published': '2020-01-28T01:15:00', 'Modified': '2020-01-28T01:52:00', 'Description': "An issue was discovered in WSO2 API Manager 2.6.0, WSO2 IS as Key Manager 5.7.0, and WSO2 Identity Server 5.8.0. When a custom claim dialect with an XSS payload is configured in the identity provider basic claim configuration, that payload gets executed, if a user picks up that dialect's URI as the provisioning claim in the advanced claim configuration of the same Identity Provider. The attacker also needs to have privileges to log in to the management console, and to add and update identity provider configurations."}, {'ID': 'CVE-2019-20436', 'CVSS': 5.0, 'Published': '2020-01-28T01:15:00', 'Modified': '2020-01-28T01:52:00', 'Description': "An issue was discovered in WSO2 API Manager 2.6.0, WSO2 IS as Key Manager 5.7.0, and WSO2 Identity Server 5.8.0. If there is a claim dialect configured with an XSS payload in the dialect URI, and a user picks up this dialect's URI and adds it as the service provider claim dialect while configuring the service provider, that payload gets executed. The attacker also needs to have privileges to log in to the management console, and to add and configure claim dialects."}, {'ID': 'CVE-2019-20435', 'CVSS': 5.0, 'Published': '2020-01-28T01:15:00', 'Modified': '2020-01-28T01:52:00', 'Description': 'An issue was discovered in WSO2 API Manager 2.6.0. A reflected XSS attack could be performed in the inline API documentation editor page of the API Publisher by sending an HTTP GET request with a harmful docName request parameter.'}, {'ID': 'CVE-2019-20434', 'CVSS': 5.0, 'Published': '2020-01-28T01:15:00', 'Modified': '2020-01-28T01:52:00', 'Description': 'An issue was discovered in WSO2 API Manager 2.6.0. A potential Reflected Cross-Site Scripting (XSS) vulnerability has been identified in the Datasource creation page of the Management Console.'}]}
### cicle.lu Latest CVEs
|CVSS|Description|ID|Modified|Published|
|---|---|---|---|---|
| 5.0 | An arbitrary file upload vulnerability has been discovered in the Super File Explorer app 1.0.1 for iOS. The vulnerability is located in the developer path that is accessible and hidden next to the root path. By default, there is no password set for the FTP or Web UI service. | CVE-2020-7998 | 2020-01-28T05:15:00 | 2020-01-28T05:15:00 |
| 5.0 | ASUS WRT-AC66U 3 RT 3.0.0.4.372_67 devices allow XSS via the Client Name field to the Parental Control feature. | CVE-2020-7997 | 2020-01-28T05:15:00 | 2020-01-28T05:15:00 |
| 5.0 | An authorization issue was discovered in GitLab EE < 12.1.2, < 12.0.4, and < 11.11.6 allowing the merge request approval rules to be overridden without appropriate permissions. | CVE-2019-5474 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | An authorization issue was discovered in Gitlab versions < 12.1.2, < 12.0.4, and < 11.11.6 that prevented owners and maintainer to delete epic comments. | CVE-2019-5472 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | An information disclosure issue was discovered GitLab versions < 12.1.2, < 12.0.4, and < 11.11.6 in the security dashboard which could result in disclosure of vulnerability feedback information. | CVE-2019-5470 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | An privilege escalation issue was discovered in Gitlab versions < 12.1.2, < 12.0.4, and < 11.11.6 when Mattermost slash commands are used with a blocked account. | CVE-2019-5468 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | An IDOR was discovered in GitLab CE/EE 11.5 and later that allowed new merge requests endpoint to disclose label names. | CVE-2019-5466 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | An information disclosure issue was discovered in GitLab CE/EE 8.14 and later, by using the move issue feature which could result in disclosure of the newly created issue ID. | CVE-2019-5465 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | A flawed DNS rebinding protection issue was discovered in GitLab CE/EE 10.2 and later in the `url_blocker.rb` which could result in SSRF where the library is utilized. | CVE-2019-5464 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | A privilege escalation issue was discovered in GitLab CE/EE 9.0 and later when trigger tokens are not rotated once ownership of them has changed. | CVE-2019-5462 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | A stored XSS vulnerability is present within node-red (version: <= 0.20.7) npm package, which is a visual tool for wiring the Internet of Things. This issue will allow the attacker to steal session cookies, deface web applications, etc. | CVE-2019-15607 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | An access control issue exists in < 12.3.5, < 12.2.8, and < 12.1.14 for GitLab Community Edition (CE) and Enterprise Edition (EE) where private merge requests and issues would be disclosed with the Group Search feature provided by Elasticsearch integration | CVE-2019-15590 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | A XSS exists in Gitlab CE/EE < 12.1.10 in the Mermaid plugin. | CVE-2019-15586 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | Improper authentication exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) in the GitLab SAML integration had a validation issue that permitted an attacker to takeover another user's account. | CVE-2019-15585 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | An information disclosure exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE). When an issue was moved to a public project from a private one, the associated private labels and the private project namespace would be disclosed through the GitLab API. | CVE-2019-15583 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | An IDOR was discovered in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) that allowed a maintainer to add any private group to a protected environment. | CVE-2019-15582 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | An IDOR exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) that allowed a project owner or maintainer to see the members of any private group via merge request approval rules. | CVE-2019-15581 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | An information disclosure exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE) where the assignee(s) of a confidential issue in a private project would be disclosed to a guest via milestones. | CVE-2019-15579 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | An information disclosure exists in < 12.3.2, < 12.2.6, and < 12.1.12 for GitLab Community Edition (CE) and Enterprise Edition (EE). The path of a private project, that used to be public, would be disclosed in the unsubscribe email link of issues and merge requests. | CVE-2019-15578 | 2020-01-28T03:15:00 | 2020-01-28T03:15:00 |
| 5.0 | A XSS vulnerability was found in Apache NiFi 1.0.0 to 1.10.0. Malicious scripts could be injected to the UI through action by an unaware authenticated user in Firefox. Did not appear to occur in other browsers. | CVE-2020-1933 | 2020-01-28T01:52:00 | 2020-01-28T01:15:00 |
| 5.0 | An information disclosure issue was found in Apache Superset 0.34.0, 0.34.1, 0.35.0, and 0.35.1. Authenticated Apache Superset users are able to retrieve other users' information, including hashed passwords, by accessing an unused and undocumented API endpoint on Apache Superset. | CVE-2020-1932 | 2020-01-28T01:52:00 | 2020-01-28T01:15:00 |
| 5.0 | An information disclosure vulnerability was found in Apache NiFi 1.10.0. The sensitive parameter parser would log parsed values for debugging purposes. This would expose literal values entered in a sensitive property when no parameter was present. | CVE-2020-1928 | 2020-01-28T01:52:00 | 2020-01-28T01:15:00 |
| 5.0 | Cleanup errors in some data cache evictions for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access. | CVE-2020-0549 | 2020-01-28T01:52:00 | 2020-01-28T01:15:00 |
| 5.0 | Cleanup errors in some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access. | CVE-2020-0548 | 2020-01-28T01:52:00 | 2020-01-28T01:15:00 |
| 5.0 | An issue was discovered in WSO2 API Manager 2.6.0. A potential Reflected Cross-Site Scripting (XSS) vulnerability has been identified in defining a scope in the "manage the API" page of the API Publisher. | CVE-2019-20439 | 2020-01-28T01:52:00 | 2020-01-28T01:15:00 |
| 5.0 | An issue was discovered in WSO2 API Manager 2.6.0. A potential stored Cross-Site Scripting (XSS) vulnerability has been identified in the inline API documentation editor page of the API Publisher. | CVE-2019-20438 | 2020-01-28T01:52:00 | 2020-01-28T01:15:00 |
| 5.0 | An issue was discovered in WSO2 API Manager 2.6.0, WSO2 IS as Key Manager 5.7.0, and WSO2 Identity Server 5.8.0. When a custom claim dialect with an XSS payload is configured in the identity provider basic claim configuration, that payload gets executed, if a user picks up that dialect's URI as the provisioning claim in the advanced claim configuration of the same Identity Provider. The attacker also needs to have privileges to log in to the management console, and to add and update identity provider configurations. | CVE-2019-20437 | 2020-01-28T01:52:00 | 2020-01-28T01:15:00 |
| 5.0 | An issue was discovered in WSO2 API Manager 2.6.0, WSO2 IS as Key Manager 5.7.0, and WSO2 Identity Server 5.8.0. If there is a claim dialect configured with an XSS payload in the dialect URI, and a user picks up this dialect's URI and adds it as the service provider claim dialect while configuring the service provider, that payload gets executed. The attacker also needs to have privileges to log in to the management console, and to add and configure claim dialects. | CVE-2019-20436 | 2020-01-28T01:52:00 | 2020-01-28T01:15:00 |
| 5.0 | An issue was discovered in WSO2 API Manager 2.6.0. A reflected XSS attack could be performed in the inline API documentation editor page of the API Publisher by sending an HTTP GET request with a harmful docName request parameter. | CVE-2019-20435 | 2020-01-28T01:52:00 | 2020-01-28T01:15:00 |
| 5.0 | An issue was discovered in WSO2 API Manager 2.6.0. A potential Reflected Cross-Site Scripting (XSS) vulnerability has been identified in the Datasource creation page of the Management Console. | CVE-2019-20434 | 2020-01-28T01:52:00 | 2020-01-28T01:15:00 |


### 3. cve
---
Search CVE by ID

##### Base Command

`cve`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | A comma separated list of CVE IDs to search. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. | 
| CVE.CVSS | String | The CVSS score of the CVE. | 
| CVE.Published | Date | The date the CVE was published. | 
| CVE.Modified | Date | The date the CVE was last modified. | 
| CVE.Description | String | The description of the CVE. | 


##### Command Example
```!cve cve_id=CVE-2014-1234```

##### Context Example
```
{
    "CVE": [
        {
            "ID": "CVE-2014-1234", 
            "Published": "2014-01-10T12:02:00", 
            "CVSS": 2.1, 
            "Modified": "2014-01-10T17:57:00", 
            "Description": "The paratrooper-newrelic gem 1.0.1 for Ruby allows local users to obtain the X-Api-Key value by listing the curl process."
        }
    ]
}
```

##### Human Readable Output
Integration log: {'CVE(val.ID === obj.ID)': [{'ID': 'CVE-2014-1234', 'CVSS': 2.1, 'Published': '2014-01-10T12:02:00', 'Modified': '2014-01-10T17:57:00', 'Description': 'The paratrooper-newrelic gem 1.0.1 for Ruby allows local users to obtain the X-Api-Key value by listing the curl process.'}]}
### CVE Search results
|CVSS|Description|ID|Modified|Published|
|---|---|---|---|---|
| 2.1 | The paratrooper-newrelic gem 1.0.1 for Ruby allows local users to obtain the X-Api-Key value by listing the curl process. | CVE-2014-1234 | 2014-01-10T17:57:00 | 2014-01-10T12:02:00 |


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
* str(err)
* 'Error occurred while trying to query the api.'
* "cve_id argument not given"
* f'Failed to execute {demisto.command()}
* f'{command} is not an existing CVE Search command'
