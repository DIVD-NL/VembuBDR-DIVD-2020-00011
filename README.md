# VembuBDR-DIVD-2020-00011

Scripts to test for various CVEs in VembuDBR

## Test environment scripts

These scripts start and kill a test environment:
* setup.sh
* kill.sh

## nmap NSE scripts

* vembu-vuln-cve-2021-26471 - tests for Unauthenticated remote command execution via StoreFolder command (CVE-2021-26471)
* vembu-vuln-cve-2021-26472 - tests for Unauthenticated remote command execution with SYSTEM privileges via download.php (CVE-2021-26472)
* vembu-vuln-cve-2021-26473 - tests for Unauthenticated arbitrary file upload and command execution (CVE-2021-26473)
* vembu-vuln-cve-2021-26474 - tests for Unauthenticated server side request forgery (CVE-2021-26474)
