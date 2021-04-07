# Security Policy
This document outlines security policy and procedures for the CrowdStrike `FDR Connector` project.
+ [Supported Python versions](#supported-python-versions)
+ [Supported FDR Connector versions](#supported-fdr-connector-versions)
+ [Reporting a potential security vulnerability](#reporting-a-potential-security-vulnerability)
+ [Disclosure and Mitigation Process](#disclosure-and-mitigation-process)

## Supported Python versions

FDR Connector functionality is unit tested to run under the following versions of Python.

| Version | Supported |
| :------- | :--------- |
| 3.9.x   | :white_check_mark: |
| 3.8.x   | :white_check_mark: |
| 3.7.x   | :white_check_mark: |
| 3.6.x   | :white_check_mark: |
| <= 3.5  | :x: |
| <= 2.x.x | :x: |

## Supported FDR Connector versions

When discovered, we release security vulnerability patches for the most recent release at an accelerated cadence.  

## Reporting a potential security vulnerability

Please report suspected security vulnerabilities by:
+ Submitting a [bug](https://github.com/CrowdStrike/FDR/issues)
+ Submitting a [pull request](https://github.com/CrowdStrike/FDR/pulls) to potentially resolve the issue

## Disclosure and mitigation process

Upon receiving a security bug report, the issue will be assigned to one of the project maintainers. This person will coordinate the related fix and release
process, involving the following steps:
+ Communicate with you to confirm we have received the report and provide you with a status update.
    - You should receive this message within 48 - 72 business hours.
+ Confirmation of the issue and a determination of affected versions.
+ An audit of the codebase to find any potentially similar problems.
+ Preparation of patches for all releases still under maintenance.
    - These patches will be submitted as a separate pull request and contain a version update.
    - This pull request will be flagged as a security fix.

## Comments
If you have suggestions on how this process could be improved, please let us know by [submitting an issue](https://github.com/CrowdStrike/FDR/issues).
