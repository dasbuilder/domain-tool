# Domain Tool
Checks DNS and SSL information via command line

* Prints out SSL information for a site
* Needs the following environment variables set
    - 'CDNCHECK' (a specific URL to check for uptime)
    - 'SITE' (A header used to determine a site's name)
    - 'CID' (A header used to determin a site's server)

#### To-Do
* Testing of classes and methods

---

# Change Log

## [0.1] - 2018-04-01
- Have a slightly working version with basic dig command output for A record, CNAME and nameservers

## [0.2] - 2018-04-07
- Updated script to include more output, for MX, TXT, etc

## [0.5] - 2019-01-27
### Added
- argparse to properly get menu items

## [0.6] - 2019-02-14
### Added
- Support for SOA, WHOIS and other output
### Changed
- subprocess.check_output to subprocess.run

## [0.7] - 2020-02-20
### Added
- dig has its own class
- Whois has its own class

## [0.8] - 2020-06-01
### Added
- Ability to detect and remove protocol, and trailing slash

## [0.9] - 2020-12-01
### Updated
- Removed specific references, these are now stored as environment variables

## [1.0] - 2020-12-15
### Updated
- Fixed output not happening for Hostcheck records
- Removed duplicate notes

## [1.1] - 2020-12-16
### Updated
- Name of program
- Formatting