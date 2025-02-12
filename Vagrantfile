Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

  config.vm.synced_folder "./module", "/otp_module"
  config.vm.synced_folder "./utilitaire", "/otp_utilitaire"

  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "1024"
  end
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y gcc make build-essential kmod linux-source
    apt-get install -y fish
  SHELL
end
