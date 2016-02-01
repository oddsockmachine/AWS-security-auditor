# A tool for automated security auditing of AWS accounts

## Overview:

* Scans all regions, instances and security groups
* Searches for risks that could compromise your servers
* Generates a website detailing the risks
* Sends email alerts to account owners when new risks appear

## Details:

* Uses boto to get data from AWS. Expects credentials in the ~/.boto file.
* Stores data in sqlite3 database for easy querying and backups.
* Dynamically generates a static web-based report of all findings. This can be served by Apache, Nginx etc.
* Compares recent findings with historical data to determine changes.
* Sends emails using AWS SES.

## Coming soon:

* Docker support for easy deployment
