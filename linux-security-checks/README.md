# Requirements: Linux Security Checks

1. Determine What Linux OS is running with build/os info version and date?
2. Must determine the users in the sudeors file? If none exist, then fail test
3. Check to see if logging is enabled
4. Passwords are greater than 8 characters are enforced
5. Checks SUID/SGID binaries and critical file permissions

# Custom InSpec profile covers the above requirements with the following detailed controls.

1. os-info-check: Gathers OS information using both InSpec's built-in OS resource and the uname command
2. sudoers-check: Verifies that there are active (non-commented) sudoers entries
3. logging-check: Checks both rsyslog and systemd-journald services and verifies log file existence
4. password-policy-check: Verifies password length requirements in both login.defs and PAM configuration
5. suid-sgid-check: Checks for several critical security concerns - Critical File Permissions, Verifies permissions on sensitive files like /etc/passwd, /etc/shadow, etc. and ensures these files aren't readable/writable by unauthorized users
