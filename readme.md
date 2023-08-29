# My-Security

PowerShell module that works with the various Microsoft Security APIs.

## Installation

The `install.ps1` script will create a locally signed certificate and sign
the PowerShell module so it can be run with the `AllSigned` Execution Policy. The
script will also copy the my-security.template.json to the my-security.json so
that default parameters for the `Get-Token` and `Get-GraphToken`.

## Status: BETA!
I consider this module a work in progress so some functions may be added, but do 
not work or do not work as expected