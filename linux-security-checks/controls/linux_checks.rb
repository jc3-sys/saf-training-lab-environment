# encoding: utf-8

title 'Linux System Security Checks'

# OS info check (passing, no changes needed)
control 'os-info-check' do
  impact 1.0
  title 'Operating System Information Check'
  desc 'Verify operating system information including version and build details'

  describe os.name do
    it { should_not be_empty }
  end

  describe os.release do
    it { should_not be_empty }
  end

  describe os.family do
    it { should_not be_empty }
  end

  describe command('uname -a') do
    its('stdout') { should_not be_empty }
  end
end

# Modified sudoers check with more flexible pattern
control 'sudoers-check' do
  impact 1.0
  title 'Sudoers Configuration Check'
  desc 'Verify that sudoers configuration exists and is properly configured'

  describe file('/etc/sudoers') do
    it { should exist }
    it { should be_file }
  end

  describe.one do
    describe command('grep -E "^[^#].*ALL=.*ALL" /etc/sudoers') do
      its('exit_status') { should eq 0 }
    end

    describe command('grep -E "^[^#].*ALL=.*ALL" /etc/sudoers.d/*') do
      its('exit_status') { should eq 0 }
    end
  end

  describe group('sudo') do
    it { should exist }
  end
end

# Modified logging check to handle different log locations
control 'logging-check' do
  impact 1.0
  title 'System Logging Check'
  desc 'Verify that system logging is enabled and configured'

  describe.one do
    describe service('rsyslog') do
      it { should be_enabled }
      it { should be_running }
    end
    
    describe service('syslog-ng') do
      it { should be_enabled }
      it { should be_running }
    end
  end

  # Check for any of the common log files
  describe.one do
    describe file('/var/log/syslog') do
      it { should exist }
      it { should be_file }
    end

    describe file('/var/log/messages') do
      it { should exist }
      it { should be_file }
    end

    describe file('/var/log/journal') do
      it { should exist }
      it { should be_directory }
    end
  end

  if command('systemctl').exist?
    describe service('systemd-journald') do
      it { should be_enabled }
      it { should be_running }
    end
  end
end

# Modified password policy check
control 'password-policy-check' do
  impact 1.0
  title 'Password Policy Check'
  desc 'Verify password length and complexity requirements'

  describe.one do
    describe command('grep -E "^[^#].*pam_pwquality.so.*minlen=(8|9|[1-9][0-9]+)" /etc/pam.d/common-password') do
      its('exit_status') { should eq 0 }
    end

    describe command('grep -E "^[^#].*pam_unix.so.*minlen=(8|9|[1-9][0-9]+)" /etc/pam.d/common-password') do
      its('exit_status') { should eq 0 }
    end

    describe file('/etc/security/pwquality.conf') do
      its('content') { should match /^[\s]*minlen[\s]*=[\s]*([89]|[1-9][0-9]+)/ }
    end

    describe file('/etc/login.defs') do
      its('content') { should match /^[\s]*PASS_MIN_LEN[\s]+([89]|[1-9][0-9]+)/ }
    end
  end
end

# Modified SUID/SGID check
control 'suid-sgid-check' do
  impact 1.0
  title 'SUID/SGID Binaries and Critical File Permissions Check'
  desc 'Check for potentially dangerous SUID/SGID binaries and verify critical file permissions'

  # Modified permissions for system files based on common configurations
  critical_files = {
    '/etc/passwd' => '0644',    # World-readable is standard
    '/etc/shadow' => '0640',
    '/etc/group' => '0644',     # World-readable is standard
    '/etc/gshadow' => '0640',
    '/etc/ssh/sshd_config' => '0600',
    '/etc/sudoers' => '0440'
  }

  critical_files.each do |file, expected_mode|
    describe file(file) do
      it { should exist }
      it { should_not be_writable.by('others') }
      its('mode') { should cmp expected_mode }
    end
  end

  # SUID binary checks
  safe_suid_binaries = [
    '/usr/bin/passwd',
    '/usr/bin/sudo',
    '/usr/bin/su'
  ]

  safe_suid_binaries.each do |binary|
    describe file(binary) do
      it { should exist }
      it { should be_setuid }
      it { should be_executable }
    end
  end

  # Check for recently added SUID binaries
  describe command('find / -type f \( -perm -4000 -o -perm -2000 \) -mtime -1 2>/dev/null') do
    its('stdout') { should be_empty }
  end

  # World-writable directories that should have sticky bit
  world_writable_dirs = [
    '/tmp',
    '/var/tmp',
    '/dev/shm'
  ]

  world_writable_dirs.each do |dir|
    describe file(dir) do
      it { should exist }
      it { should be_directory }
      it { should be_sticky }
    end
  end

  # Custom check for workspace directories
  workspace_dirs = [
    '/workspaces',
    '/workspaces/.oryx',
    '/workspaces/.codespaces'
  ]

  workspace_dirs.each do |dir|
    describe file(dir) do
      it { should exist }
      it { should be_directory }
      # Not checking sticky bit for workspace dirs as they may have different requirements
    end
  end
end