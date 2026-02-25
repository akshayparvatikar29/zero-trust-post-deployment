# ------------------------------------------------------------
# Zero Trust Final State Validation - Production Web Tier
# ------------------------------------------------------------

control 'zt-ssh-hardening-01' do
  impact 1.0
  title 'SSH root login must be disabled'
  desc 'Prevents direct root access in Zero Trust environments'

  describe sshd_config do
    its('PermitRootLogin') { should cmp 'no' }
  end
end

control 'zt-ssh-hardening-02' do
  impact 1.0
  title 'SSH password authentication must be disabled'
  desc 'Ensures key-based authentication only'

  describe sshd_config do
    its('PasswordAuthentication') { should cmp 'no' }
  end
end

control 'zt-network-01' do
  impact 1.0
  title 'Port 80 must be listening for application availability'

  describe port(80) do
    it { should be_listening }
  end
end

control 'zt-network-02' do
  impact 0.7
  title 'Port 22 should not be publicly exposed (if policy enforced)'

  describe port(22) do
    it { should_not be_listening }
  end
end

control 'zt-service-baseline-01' do
  impact 1.0
  title 'demo-app service must be running'

  describe service('demo-app') do
    it { should be_running }
  end
end

control 'zt-service-baseline-02' do
  impact 0.8
  title 'demo-app service must be enabled'

  describe service('demo-app') do
    it { should be_enabled }
  end
end

control 'zt-audit-01' do
  impact 0.8
  title 'Enforcement log must exist'

  describe file('/home/ubuntu/chef360-governance-demo/enforcement.log') do
    it { should exist }
  end
end

control 'zt-audit-02' do
  impact 0.9
  title 'Enforcement log must not be world writable'

  describe file('/home/ubuntu/chef360-governance-demo/enforcement.log') do
    its('mode') { should_not cmp '0777' }
  end
end

control 'zt-integrity-01' do
  impact 0.7
  title 'demo-app service unit file must not be modified'

  describe file('/etc/systemd/system/demo-app.service') do
    it { should exist }
    it { should_not be_writable.by('others') }
  end
end
