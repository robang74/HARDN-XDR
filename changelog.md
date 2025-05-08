# Changelog

## Version 1.1.4

### Added
- **Debian Packaging**: Added support for building Debian packages for HARDN.
- **Enhanced GRUB Security**: Improved GRUB configuration to ensure compatibility with GUI changes and user-defined settings.
- **Error Handling**: Enhanced error handling in scripts to prevent disruptions to user logins or system functionality.

### Improved
- **Script Optimization**: Removed redundant steps and consolidated repetitive code blocks in setup scripts.
- **Documentation**: Updated documentation to reflect the latest changes and features.

### Fixed
- **Cron Jobs**: Ensured cron jobs are non-intrusive and do not disrupt user workflows.
- **AIDE Initialization**: Improved AIDE initialization process for better reliability.

## Version 1

### Added
- **HARDN-Endpoint**: Introduced enhanced CLI-based support for ensuring STIG compliance on Debian 12.
- Added automated STIG compliance validation for Debian 12, integrated into the CLI workflow.
- Replace UFW with IPTables for more granular Firewall control and policies. 
- ASCII banner

### Improved
- Kernel principles to align with NIST best practices. 

### Fixed
- Aide load and database directory build

---

*Note*: For detailed CLI usage instructions, refer to the [documentation](https://github.com/OpenSource-For-Freedom/HARDN/blob/main/README.md).