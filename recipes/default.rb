#
# Cookbook Name:: openssh
# Recipe:: default
#
# Copyright 2008-2009, Opscode, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

packages = case node[:platform]
  when "centos","redhat","fedora"
    %w{openssh-clients openssh}
  when "arch"
    %w{openssh}
  else
    %w{openssh-client openssh-server}
  end
  
packages.each do |pkg|
  package pkg
end

template "/etc/ssh/sshd_config" do
  source "sshd_config.erb"
  variables( 
    :Port => "22"
    :AddressFamily => "any"
    :ListenAddress1 => "0.0.0.0"
    :ListenAddress2 => "::"
    :Protocol => "2"
    :HostKey1 => "/etc/ssh/ssh_host_key"
    :HostKey2 => "/etc/ssh/ssh_host_rsa_key"
    :HostKey3 => "/etc/ssh/ssh_host_dsa_key"
    :KeyRegenerationInterval => "1h"
    :ServerKeyBits => "1024"
    :SyslogFacility => "AUTH"
    :LogLevel => "INFO"
    :LoginGraceTime => "2m"
    :PermitRootLogin => "yes"
    :StrictModes => "yes"
    :MaxAuthTries => "6"
    :MaxSessions => "10"
    :RSAAuthentication => "yes"
    :PubkeyAuthentication => "yes"
    :AuthorizedKeysFile => ".ssh/authorized_keys"
    :RhostsRSAAuthentication => "no"
    :HostbasedAuthentication => "no"
    :IgnoreUserKnownHosts => "no"
    :IgnoreRhosts => "yes"
    :PasswordAuthentication => "yes"
    :PermitEmptyPasswords => "no"
    :ChallengeResponseAuthentication => "yes"
    :KerberosAuthentication => "no"
    :KerberosOrLocalPasswd => "yes"
    :KerberosTicketCleanup => "yes"
    :KerberosGetAFSToken => "no"
    :GSSAPIAuthentication => "no"
    :GSSAPICleanupCredentials => "yes"
    :UsePAM => "no"
    :AllowAgentForwarding => "yes"
    :AllowTcpForwarding => "yes"
    :GatewayPorts => "no"
    :X11Forwarding => "no"
    :X11DisplayOffset => "10"
    :X11UseLocalhost => "yes"
    :PrintMotd => "yes"
    :PrintLastLog => "yes"
    :TCPKeepAlive => "yes"
    :UseLogin => "no"
    :UsePrivilegeSeparation => "yes"
    :PermitUserEnvironment => "no"
    :Compression => "delayed"
    :ClientAliveInterval => "0"
    :ClientAliveCountMax => "3"
    :UseDNS => "yes"
    :PidFile => "/var/run/sshd.pid"
    :MaxStartups => "10"
    :PermitTunnel => "no"
    :ChrootDirectory => "none"
    :Banner => "none"
    :Subsystem => "sftp /usr/libexec/sftp-server"
  )
end

service "ssh" do
  case node[:platform]
  when "centos","redhat","fedora","arch"
    service_name "sshd"
  else
    service_name "ssh"
  end
  supports value_for_platform(
    "debian" => { "default" => [ :restart, :reload, :status ] },
    "ubuntu" => {
      "8.04" => [ :restart, :reload ],
      "default" => [ :restart, :reload, :status ]
    },
    "centos" => { "default" => [ :restart, :reload, :status ] },
    "redhat" => { "default" => [ :restart, :reload, :status ] },
    "fedora" => { "default" => [ :restart, :reload, :status ] },
    "arch" => { "default" => [ :restart ] },
    "default" => { "default" => [:restart, :reload ] }
  )
  action [ :enable, :start ]
end
