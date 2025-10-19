# Release Notes

## Changes from 2f6320a to 675a10a

### API Improvements
- Reworked API structure and reimplemented HTTP-01 challenge (#53)
- Improved error message handling in API responses
- Fixed HTTP method routing issues
- Added debug logging for better troubleshooting
- Matched SignatureAlgorithm for GenerateCertificateByCSR() function

### Challenge System
- Completed challenge solving implementation
- Reworked challenge structure for better organization
- Implemented HTTP-01 challenge support

### Certificate Generation
- Refactored certificate generators for improved maintainability
- Removed unnecessary field from SimpleRequest entity
- Fixed user entity type assertion issues

### UI/Frontend
- Integrated Bootstrap framework for improved styling
- Reworked UI templates and handlers for better maintainability
- Added user messages and feedback notifications (#24)
- Improved template structure and functionality
- Removed outdated UI screenshots from documentation

### Documentation
- Updated and brought all documentation up-to-date
- Added navigation links to documentation pages
- Improved tool descriptions in README
- Fixed various typos throughout documentation
- Cleaned up configuration and security documentation
- Removed deprecated UI documentation

### Code Quality
- Improved constant naming conventions throughout codebase
- Enhanced global constant usage for better consistency
- Quality of life updates and code cleanup
