# encoding: utf-8

# Control name: rootkit-access-check
# Description: Comprehensive rootkit detection and system access control verification
# Checks performed:
# 1. Chkrootkit Installation and Execution
# 2. Known Rootkit Signatures
# 3. File Integrity
# 4. System Access Controls
# 5. Suspicious Processes
# 6. Network Connections
# 7. Critical System Files

control 'rootkit-access-check' do
  impact 1.0
  title 'Rootkit Detection and System Access Control Verification'
  desc 'Comprehensive check for rootkits and system access control verification including file integrity, processes, and network connections'
  
  tag 'security'
  tag 'rootkit'
  tag 'system-access'

  # 1. Check Chkrootkit Installation
  describe package('chkrootkit') do
    it { should be_installed }
  end

  # 2. Run Chkrootkit Scan
  describe command('chkrootkit') do
    its('exit_status') { should eq 0 }
    its('stdout') { should_not match(/INFECTED/) }
    its('stdout') { should_not match(/warning/i) }
    its('stderr') { should_not match(/error|fail/i) }
  end

  # 3. Check File Integrity
  describe command('find /bin /sbin /usr/bin /usr/sbin -type f -mtime -1') do
    its('stdout') { should be_empty }
  end

  # 4. Check Critical System Files for Modifications
  %w(/bin/login /bin/ls /bin/ps /bin/netstat /sbin/ifconfig).each do |file|
    describe file(file) do
      it { should exist }
      it { should_not be_writable.by('group') }
      it { should_not be_writable.by('others') }
      its('mode') { should cmp '0755' }
    end
  end

  # 5. Check for Hidden Processes
  describe command('ps auxf | grep -v grep | grep "^[[:space:]]*\["') do
    its('stdout') { should be_empty }
  end

  # 6. Check for Suspicious Network Connections
  describe command('netstat -tulpn | grep LISTEN') do
    its('exit_status') { should eq 0 }
    its('stdout') { should_not match(/0\.0\.0\.0:.*LISTEN/) }
  end

  # 7. Check for Suspicious Loaded Kernel Modules
  describe command('lsmod') do
    its('stdout') { should_not match(/hide_proc|hp_mod|kisni|mood/) }
  end

  # 8. Check System Access Controls
  describe file('/etc/security/access.conf') do
    it { should exist }
    it { should be_file }
    it { should_not be_readable.by('others') }
    its('mode') { should cmp '0644' }
  end

  # 9. Check SELinux/AppArmor Status
  describe.one do
    describe command('sestatus') do
      its('stdout') { should match(/enabled|enforcing/) }
    end
    
    describe command('apparmor_status') do
      its('stdout') { should match(/profiles are loaded/) }
    end
  end

  # 10. Check for Unauthorized SUID/SGID Files
  describe command('find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "/proc/*" 2>/dev/null') do
    its('stdout') { should_not match(%r{
      (?!(/usr/bin/sudo|/usr/bin/su|/usr/bin/passwd|/usr/bin/chage|/usr/bin/gpasswd|/usr/bin/newgrp))
      (/[^\s]+)
    }x) }
  end
end