#! /usr/bin/env bash
# shellcheck disable=SC1091,SC2129

# This is the script that is used to provision the logger host
# Updated for Ubuntu 24.04

# Configure DNS - Ubuntu 24.04 uses systemd-resolved differently
configure_dns() {
  echo "[$(date +%H:%M:%S)]: Configuring DNS settings..."
  # Check if we're running in AWS
  if ! curl -s 169.254.169.254 --connect-timeout 2 >/dev/null; then
    # We're not in AWS, configure DNS for lab environment
    mkdir -p /etc/systemd/resolved.conf.d/
    cat <<EOF > /etc/systemd/resolved.conf.d/dns_servers.conf
[Resolve]
DNS=8.8.8.8 8.8.4.4 192.168.57.102
DNSStubListener=yes
EOF
    systemctl restart systemd-resolved
  fi
}

# Source variables from logger_variables.sh
# shellcheck disable=SC1091
source /vagrant/logger_variables.sh 2>/dev/null ||
  source /home/vagrant/logger_variables.sh 2>/dev/null ||
  echo "Unable to locate logger_variables.sh"

if [ -z "$MAXMIND_LICENSE" ]; then
  echo "Note: You have not entered a MaxMind API key in logger_variables.sh, so the ASNgen Splunk app may not work correctly."
  echo "However, it is optional and everything else should function correctly."
fi

export DEBIAN_FRONTEND=noninteractive

apt_install_prerequisites() {
  echo "[$(date +%H:%M:%S)]: Running apt-get update..."
  apt-get -qq update
  echo "[$(date +%H:%M:%S)]: Installing prerequisites..."
  
  # Just use apt-get directly - avoid apt-fast complications
  echo "[$(date +%H:%M:%S)]: Installing packages..."
  apt-get install -y jq whois build-essential git unzip htop yq mysql-server redis-server python3-pip python3-venv libcairo2-dev libjpeg-turbo8-dev libpng-dev libtool-bin libossp-uuid-dev libavcodec-dev libavutil-dev libswscale-dev freerdp2-dev libpango1.0-dev libssh2-1-dev libvncserver-dev libtelnet-dev libssl-dev libvorbis-dev libwebp-dev tomcat10 tomcat10-admin tomcat10-user net-tools suricata crudini curl gnupg2
}

modify_motd() {
  echo "[$(date +%H:%M:%S)]: Updating the MOTD..."
  # Force color terminal
  sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/g' /root/.bashrc
  sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/g' /home/vagrant/.bashrc
  # Remove some stock Ubuntu MOTD content
  chmod -x /etc/update-motd.d/10-help-text
  # Copy the DetectionLab MOTD
  cp /vagrant/resources/logger/20-detectionlab /etc/update-motd.d/
  chmod +x /etc/update-motd.d/20-detectionlab
}

test_prerequisites() {
  for package in jq whois build-essential git unzip yq mysql-server redis-server python3-pip; do
    echo "[$(date +%H:%M:%S)]: [TEST] Validating that $package is correctly installed..."
    
    # Use dpkg -l to check if package is installed
    if ! dpkg -l | grep -q "^ii.*$package"; then
      echo "[-] $package was not found. Attempting to reinstall."
      apt-get -qq update && apt-get install -y $package
      if ! dpkg -l | grep -q "^ii.*$package"; then
        echo "[X] Unable to install $package even after a retry. Exiting."
        exit 1
      fi
    else
      echo "[+] $package was successfully installed!"
    fi
  done
}

fix_eth1_static_ip() {
  USING_KVM=$(sudo lsmod | grep kvm)
  if [ -n "$USING_KVM" ]; then
    echo "[*] Using KVM, no need to fix DHCP for eth1 iface"
    return 0
  fi
  if [ -f /sys/class/net/eth2/address ]; then
    if [ "$(cat /sys/class/net/eth2/address)" == "00:50:56:a3:b1:c4" ]; then
      echo "[*] Using ESXi, no need to change anything"
      return 0
    fi
  fi
  
  # Use systemd-networkd for interface configuration in Ubuntu 24.04
  cat <<EOF > /etc/systemd/network/10-eth1-static.network
[Match]
Name=eth1

[Network]
Address=192.168.57.105/24
DNS=8.8.8.8
DNS=8.8.4.4
EOF

  systemctl restart systemd-networkd

  # Fix eth1 if the IP isn't set correctly
  ETH1_IP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
  if [ "$ETH1_IP" != "192.168.57.105" ]; then
    echo "Incorrect IP Address settings detected. Attempting to fix."
    ip link set dev eth1 down
    ip addr flush dev eth1
    ip link set dev eth1 up
    ip addr add 192.168.57.105/24 dev eth1
    counter=0
    while :; do
      ETH1_IP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
      if [ "$ETH1_IP" == "192.168.57.105" ]; then
        echo "[$(date +%H:%M:%S)]: The static IP has been fixed and set to 192.168.57.105"
        break
      else
        if [ $counter -le 20 ]; then
          let counter=counter+1
          echo "[$(date +%H:%M:%S)]: Waiting for IP $counter/20 seconds"
          sleep 1
          continue
        else
          echo "[$(date +%H:%M:%S)]: Failed to fix the broken static IP for eth1. Exiting because this will cause problems with other VMs."
          echo "[$(date +%H:%M:%S)]: eth1's current IP address is $ETH1_IP"
          exit 1
        fi
      fi
    done
  fi

  # Make sure we do have a DNS resolution
  while true; do
    if [ "$(dig +short @8.8.8.8 github.com)" ]; then break; fi
    sleep 1
  done
}
install_splunk() {
  if [ -x "/opt/splunk/bin/splunk" ]; then
    SPLUNK_INSTALLED=1
    CURRENT_VERSION=$(/opt/splunk/bin/splunk version 2>/dev/null | awk '{print $2}')
    echo "[$(date +%H:%M:%S)]: Splunk is already installed (version ${CURRENT_VERSION:-unknown})"
  else
    SPLUNK_INSTALLED=0
    CURRENT_VERSION=""
    echo "[$(date +%H:%M:%S)]: Splunk is not installed. Proceeding with installation..."
  fi

  # Get download.splunk.com into the DNS cache. Sometimes resolution randomly fails during wget below
  dig @8.8.8.8 download.splunk.com >/dev/null
  dig @8.8.8.8 splunk.com >/dev/null
  dig @8.8.8.8 www.splunk.com >/dev/null

  # Try to resolve the latest version of Splunk by parsing the HTML on the downloads page
  echo "[$(date +%H:%M:%S)]: Attempting to autoresolve the latest version of Splunk..."
  SPLUNK_FALLBACK_VERSION="10.0.0"
  SPLUNK_FALLBACK_BUILD="e8eb0c4654f8"
  SPLUNK_FALLBACK_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_FALLBACK_VERSION}/linux/splunk-${SPLUNK_FALLBACK_VERSION}-${SPLUNK_FALLBACK_BUILD}-linux-amd64.deb"
  LATEST_SPLUNK=$(python3 - 2>/dev/null <<'PY'
import re, sys, urllib.request
try:
    with urllib.request.urlopen('https://www.splunk.com/en_us/download/splunk-enterprise.html', timeout=30) as resp:
        html = resp.read().decode('utf-8', 'ignore')
except Exception:
    sys.exit(0)
match = re.search(r'data-link="(https://download\.splunk\.com/products/splunk/releases/[0-9.]+/linux/splunk-[^"]+-linux-amd64\.deb)"', html)
if match:
    print(match.group(1))
PY
)

  if [[ -n "$LATEST_SPLUNK" ]]; then
    DOWNLOAD_URL="$LATEST_SPLUNK"
    echo "[$(date +%H:%M:%S)]: The URL to the latest Splunk version was automatically resolved as: $DOWNLOAD_URL"
  else
    DOWNLOAD_URL="$SPLUNK_FALLBACK_URL"
    echo "[$(date +%H:%M:%S)]: Unable to auto-resolve the latest Splunk version. Falling back to: $DOWNLOAD_URL"
  fi

  # Ensure we don't install an older cached package
  rm -f /opt/splunk-*-linux-amd64.deb
  SPLUNK_DEB_PATH="/opt/$(basename "$DOWNLOAD_URL")"
  TARGET_VERSION=$(basename "$DOWNLOAD_URL" | cut -d'-' -f2)
  echo "[$(date +%H:%M:%S)]: Downloading Splunk package from $DOWNLOAD_URL..."
  wget --progress=bar:force -O "$SPLUNK_DEB_PATH" "$DOWNLOAD_URL"

  if ! ls /opt/splunk*.deb 1>/dev/null 2>&1; then
    echo "Something went wrong while trying to download Splunk. This script cannot continue. Exiting."
    exit 1
  fi

  INSTALL_REASON="fresh install"
  INSTALL_REQUIRED=1
  if [[ $SPLUNK_INSTALLED -eq 1 ]]; then
    if [[ -n "$CURRENT_VERSION" ]] && [[ "$CURRENT_VERSION" == "$TARGET_VERSION" ]]; then
      INSTALL_REQUIRED=0
      echo "[$(date +%H:%M:%S)]: Splunk $CURRENT_VERSION is already installed. Skipping installer."
    else
      INSTALL_REASON="upgrade from ${CURRENT_VERSION:-unknown}"
      echo "[$(date +%H:%M:%S)]: Upgrading Splunk from ${CURRENT_VERSION:-unknown} to $TARGET_VERSION..."
    fi
  fi

  if [[ $INSTALL_REQUIRED -eq 1 ]]; then
    if [[ $SPLUNK_INSTALLED -eq 1 ]]; then
      /opt/splunk/bin/splunk stop --accept-license --answer-yes --no-prompt || true
    fi

    if ! dpkg -i "$SPLUNK_DEB_PATH" >/dev/null; then
      echo "Something went wrong while trying to install Splunk. This script cannot continue. Exiting."
      exit 1
    fi

    /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd changeme

    if [[ "$INSTALL_REASON" == "fresh install" ]]; then
      /opt/splunk/bin/splunk add index wineventlog -auth 'admin:changeme'
      /opt/splunk/bin/splunk add index osquery -auth 'admin:changeme'
      /opt/splunk/bin/splunk add index osquery-status -auth 'admin:changeme'
      /opt/splunk/bin/splunk add index sysmon -auth 'admin:changeme'
      /opt/splunk/bin/splunk add index powershell -auth 'admin:changeme'
      /opt/splunk/bin/splunk add index zeek -auth 'admin:changeme'
      /opt/splunk/bin/splunk add index suricata -auth 'admin:changeme'
      /opt/splunk/bin/splunk add index threathunting -auth 'admin:changeme'
      /opt/splunk/bin/splunk add index evtx_attack_samples -auth 'admin:changeme'
      /opt/splunk/bin/splunk add index msexchange -auth 'admin:changeme'
      /opt/splunk/bin/splunk install app /vagrant/resources/splunk_forwarder/splunk-add-on-for-microsoft-windows_700.tgz -auth 'admin:changeme'
      /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/splunk-add-on-for-microsoft-sysmon_1062.tgz -auth 'admin:changeme'
      /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/asn-lookup-generator_110.tgz -auth 'admin:changeme'
      /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/lookup-file-editor_331.tgz -auth 'admin:changeme'
      /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/splunk-add-on-for-zeek-aka-bro_400.tgz -auth 'admin:changeme'
      /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/force-directed-app-for-splunk_200.tgz -auth 'admin:changeme'
      /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/punchcard-custom-visualization_130.tgz -auth 'admin:changeme'
      /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/sankey-diagram-custom-visualization_130.tgz -auth 'admin:changeme'
      /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/link-analysis-app-for-splunk_161.tgz -auth 'admin:changeme'
      /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/threathunting_1492.tgz -auth 'admin:changeme'
      echo 'python.version = python3' >>/opt/splunk/etc/apps/TA-asngen/default/commands.conf

      if [ -n "$MAXMIND_LICENSE" ]; then
        mkdir -p /opt/splunk/etc/apps/TA-asngen/local
        cp /opt/splunk/etc/apps/TA-asngen/default/asngen.conf /opt/splunk/etc/apps/TA-asngen/local/asngen.conf
        sed -i "s/license_key =/license_key = $MAXMIND_LICENSE/g" /opt/splunk/etc/apps/TA-asngen/local/asngen.conf
      fi

      if [ -n "$BASE64_ENCODED_SPLUNK_LICENSE" ]; then
        echo "$BASE64_ENCODED_SPLUNK_LICENSE" | base64 -d >/tmp/Splunk.License
        /opt/splunk/bin/splunk add licenses /tmp/Splunk.License -auth 'admin:changeme'
        rm /tmp/Splunk.License
      fi

      cp /vagrant/resources/splunk_server/windows_ta_props.conf /opt/splunk/etc/apps/Splunk_TA_windows/default/props.conf
      cp /vagrant/resources/splunk_server/sysmon_ta_props.conf /opt/splunk/etc/apps/TA-microsoft-sysmon/default/props.conf
      mkdir -p /opt/splunk/etc/apps/Splunk_TA_bro/local && cp /vagrant/resources/splunk_server/zeek_ta_props.conf /opt/splunk/etc/apps/Splunk_TA_bro/local/props.conf
      cp /vagrant/resources/splunk_server/macros.conf /opt/splunk/etc/apps/ThreatHunting/default/macros.conf
      sed -i 's/index=windows/`windows`/g' /opt/splunk/etc/apps/ThreatHunting/default/data/ui/views/computer_investigator.xml
      sed -i 's/$host$)/$host$*)/g' /opt/splunk/etc/apps/ThreatHunting/default/data/ui/views/computer_investigator.xml
      find /opt/splunk/etc/apps/ThreatHunting -type f ! -path "/opt/splunk/etc/apps/ThreatHunting/default/props.conf" -exec sed -i -e 's/host_fqdn/ComputerName/g' {} \;
      find /opt/splunk/etc/apps/ThreatHunting -type f ! -path "/opt/splunk/etc/apps/ThreatHunting/default/props.conf" -exec sed -i -e 's/event_id/EventCode/g' {} \;
      mkdir -p /opt/splunk/etc/apps/Splunk_TA_windows/local
      cp /opt/splunk/etc/apps/Splunk_TA_windows/default/macros.conf /opt/splunk/etc/apps/Splunk_TA_windows/local
      sed -i 's/wineventlog_windows/wineventlog/g' /opt/splunk/etc/apps/Splunk_TA_windows/local/macros.conf
      rm -f /opt/splunk/etc/apps/force_directed_viz/default/savedsearches.conf
      echo -e "[splunktcp://9997]
connection_host = ip" >/opt/splunk/etc/apps/search/local/inputs.conf
      cp /vagrant/resources/splunk_server/props.conf /opt/splunk/etc/apps/search/local/
      cp /vagrant/resources/splunk_server/transforms.conf /opt/splunk/etc/apps/search/local/
      cp /opt/splunk/etc/system/default/limits.conf /opt/splunk/etc/system/local/limits.conf
      sed -i.bak 's/max_memtable_bytes = 10000000/max_memtable_bytes = 30000000/g' /opt/splunk/etc/system/local/limits.conf
      echo "[$(date +%H:%M:%S)]: Disabling the Splunk tour prompt..."
      touch /opt/splunk/etc/.ui_login
      mkdir -p /opt/splunk/etc/users/admin/search/local
      echo -e "[search-tour]
viewed = 1" >/opt/splunk/etc/system/local/ui-tour.conf
      if [ ! -d "/opt/splunk/etc/users/admin/user-prefs/local" ]; then
        mkdir -p "/opt/splunk/etc/users/admin/user-prefs/local"
      fi
      cat > /opt/splunk/etc/users/admin/user-prefs/local/user-prefs.conf <<'EOF'
[general]
render_version_messages = 1
dismissedInstrumentationOptInVersion = 4
notification_python_3_impact = false
display.page.home.dashboardId = /servicesNS/nobody/search/data/ui/views/logger_dashboard
EOF
      echo -e "[settings]
enableSplunkWebSSL = true" >/opt/splunk/etc/system/local/web.conf
      if [ ! -d "/opt/splunk/etc/apps/search/local/data/ui/views" ]; then
        mkdir -p "/opt/splunk/etc/apps/search/local/data/ui/views"
      fi
      cp /vagrant/resources/splunk_server/logger_dashboard.xml /opt/splunk/etc/apps/search/local/data/ui/views || echo "Unable to find dashboard"
      /opt/splunk/bin/splunk restart
      /opt/splunk/bin/splunk enable boot-start
    else
      /opt/splunk/bin/splunk restart
    fi
  else
    if ! /opt/splunk/bin/splunk status >/dev/null 2>&1; then
      /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt || true
    fi
  fi

  # Include Splunk and Zeek in the PATH
  echo export PATH="$PATH:/opt/splunk/bin:/opt/zeek/bin" >>~/.bashrc
  echo "export SPLUNK_HOME=/opt/splunk" >>~/.bashrc
}

download_palantir_osquery_config() {
  if [ -f /opt/osquery-configuration ]; then
    echo "[$(date +%H:%M:%S)]: osquery configs have already been downloaded"
  else
    # Import Palantir osquery configs into Fleet
    echo "[$(date +%H:%M:%S)]: Downloading Palantir osquery configs..."
    cd /opt && git clone https://github.com/palantir/osquery-configuration.git
  fi
}

install_fleet_import_osquery_config() {
  if [ -d "/opt/fleet" ]; then
    echo "[$(date +%H:%M:%S)]: Fleet is already installed"
  else
    cd /opt && mkdir -p /opt/fleet || exit 1

    echo "[$(date +%H:%M:%S)]: Installing Fleet..."
    if ! grep 'fleet' /etc/hosts; then
      echo -e "\n127.0.0.1       fleet" >>/etc/hosts
    fi
    if ! grep 'logger' /etc/hosts; then
      echo -e "\n127.0.0.1       logger" >>/etc/hosts
    fi

    # Set MySQL username and password, create fleet database
    # MySQL in Ubuntu 24.04 uses a different authentication plugin
    # Only try to set password if it hasn't been set
    mysql -uroot -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'fleet';" || echo "MySQL password may already be set"
    mysql -uroot -pfleet -e "create database fleet;" || echo "Database may already exist, continuing..."

    echo "[$(date +%H:%M:%S)]: Checking GitHub API for Fleet releases..."
    
    # Try manually getting a list of releases and picking a specific one
    RELEASES=$(curl -s "https://api.github.com/repos/fleetdm/fleet/releases")
    # Extract tags in reverse order (newest first)
    TAGS=$(echo "$RELEASES" | grep -o '"tag_name": "[^"]*' | cut -d'"' -f4)
    
    # Let's try with a specific 4.x version
    VERSION_TO_TRY="v4.67.2"
    echo "[$(date +%H:%M:%S)]: Trying Fleet version $VERSION_TO_TRY"
    
    # Construct URLs
    FLEET_URL="https://github.com/fleetdm/fleet/releases/download/$VERSION_TO_TRY/fleet_${VERSION_TO_TRY#v}_linux.tar.gz"
    FLEETCTL_URL="https://github.com/fleetdm/fleet/releases/download/$VERSION_TO_TRY/fleetctl_${VERSION_TO_TRY#v}_linux.tar.gz"
    
    echo "[$(date +%H:%M:%S)]: Testing Fleet download URL: $FLEET_URL"
    
    # Test if the URL is valid
    if curl --output /dev/null --silent --head --fail "$FLEET_URL"; then
      echo "[$(date +%H:%M:%S)]: Fleet URL is valid, downloading..."
    else
      # URL is not valid, try a different approach or version
      echo "[$(date +%H:%M:%S)]: URL not valid, trying a different approach..."
      
      # Get the latest release info and list all assets
      LATEST_RELEASE=$(curl -s "https://api.github.com/repos/fleetdm/fleet/releases/latest")
      ALL_ASSETS=$(echo "$LATEST_RELEASE" | grep -o '"browser_download_url": "[^"]*"' | cut -d'"' -f4)
      
      # Print all available assets to help debug
      echo "[$(date +%H:%M:%S)]: Available assets in latest release:"
      echo "$ALL_ASSETS"
      
      # Try to find Linux assets
      LINUX_ASSETS=$(echo "$ALL_ASSETS" | grep "linux")
      
      if [ -n "$LINUX_ASSETS" ]; then
        # Found Linux assets, try to identify fleet and fleetctl
        FLEET_URL=$(echo "$LINUX_ASSETS" | grep -v "fleetctl" | head -1)
        FLEETCTL_URL=$(echo "$LINUX_ASSETS" | grep "fleetctl" | head -1)
        
        echo "[$(date +%H:%M:%S)]: Identified Fleet URL: $FLEET_URL"
        echo "[$(date +%H:%M:%S)]: Identified Fleetctl URL: $FLEETCTL_URL"
      else
        # Fallback to manual download
        echo "[$(date +%H:%M:%S)]: Falling back to manual download method..."
        # Fetch the release page html and try to parse download links
        RELEASE_PAGE=$(curl -s "https://github.com/fleetdm/fleet/releases")
        # Look for Linux download links
        LINUX_LINKS=$(echo "$RELEASE_PAGE" | grep -o 'href="[^"]*linux[^"]*"' | cut -d'"' -f2)
        
        if [ -n "$LINUX_LINKS" ]; then
          # Convert relative links to absolute
          FLEET_URL="https://github.com$(echo "$LINUX_LINKS" | grep -v "fleetctl" | head -1)"
          FLEETCTL_URL="https://github.com$(echo "$LINUX_LINKS" | grep "fleetctl" | head -1)"
          
          echo "[$(date +%H:%M:%S)]: Parsed Fleet URL: $FLEET_URL"
          echo "[$(date +%H:%M:%S)]: Parsed Fleetctl URL: $FLEETCTL_URL"
        else
          echo "[$(date +%H:%M:%S)]: ERROR: Could not determine download URLs. Exiting."
          return 1
        fi
      fi
    fi
    
    # Final download attempt
    echo "[$(date +%H:%M:%S)]: Downloading Fleet from: $FLEET_URL"
    wget --progress=bar:force -O fleet.tar.gz "$FLEET_URL" || {
      echo "[$(date +%H:%M:%S)]: ERROR: Fleet download failed."
      return 1
    }
    
    echo "[$(date +%H:%M:%S)]: Downloading Fleetctl from: $FLEETCTL_URL"
    wget --progress=bar:force -O fleetctl.tar.gz "$FLEETCTL_URL" || {
      echo "[$(date +%H:%M:%S)]: ERROR: Fleetctl download failed."
      return 1
    }
    
    # Check if the files were downloaded correctly
    if [ ! -f fleet.tar.gz ] || [ ! -f fleetctl.tar.gz ]; then
      echo "[$(date +%H:%M:%S)]: ERROR: Could not download Fleet files. Check connectivity to GitHub."
      return 1
    fi
    
    # Create directories for extraction
    mkdir -p fleet_extracted fleetctl_extracted
    
    echo "[$(date +%H:%M:%S)]: Extracting Fleet files..."
    tar -xzf fleet.tar.gz -C fleet_extracted || {
      echo "[$(date +%H:%M:%S)]: ERROR: Could not extract fleet.tar.gz"
      return 1
    }
    
    tar -xzf fleetctl.tar.gz -C fleetctl_extracted || {
      echo "[$(date +%H:%M:%S)]: ERROR: Could not extract fleetctl.tar.gz"
      return 1
    }
    
    # Find the fleet and fleetctl binaries (they might be in subdirectories)
    FLEET_BIN=$(find fleet_extracted -name fleet -type f | head -1)
    FLEETCTL_BIN=$(find fleetctl_extracted -name fleetctl -type f | head -1)
    
    if [ -z "$FLEET_BIN" ] || [ -z "$FLEETCTL_BIN" ]; then
      echo "[$(date +%H:%M:%S)]: ERROR: Could not find binaries in extracted archives."
      # Show the structure to help diagnose
      echo "Contents of fleet_extracted:"
      find fleet_extracted -type f | sort
      echo "Contents of fleetctl_extracted:"
      find fleetctl_extracted -type f | sort
      return 1
    fi
    
    echo "[$(date +%H:%M:%S)]: Installing Fleet binaries..."
    cp "$FLEET_BIN" /usr/local/bin/fleet && chmod +x /usr/local/bin/fleet
    cp "$FLEETCTL_BIN" /usr/local/bin/fleetctl && chmod +x /usr/local/bin/fleetctl
    
    # Verify the installation
    if [ ! -x /usr/local/bin/fleetctl ] || [ ! -x /usr/local/bin/fleet ]; then
      echo "[$(date +%H:%M:%S)]: ERROR: Failed to install Fleet binaries."
      return 1
    fi

    # The rest of the function remains the same...
    echo "[$(date +%H:%M:%S)]: Preparing Fleet database..."
    # Prepare the DB
    fleet prepare db --mysql_address=127.0.0.1:3306 --mysql_database=fleet --mysql_username=root --mysql_password=fleet

    # Copy over the certs and service file
    echo "[$(date +%H:%M:%S)]: Setting up Fleet certificates and service..."
    cp /vagrant/resources/fleet/server.* /opt/fleet/
    cp /vagrant/resources/fleet/fleet.service /etc/systemd/system/fleet.service

    # Create directory for logs
    mkdir -p /var/log/fleet

    # Install the service file
    /bin/systemctl daemon-reload
    /bin/systemctl enable fleet.service
    /bin/systemctl start fleet.service

    # Start Fleet
    echo "[$(date +%H:%M:%S)]: Waiting for fleet service to start..."
    COUNTER=0
    MAX_TRIES=60
    while true; do
      result=$(curl --silent -k https://127.0.0.1:8412)
      if echo "$result" | grep -q setup; then break; fi
      COUNTER=$((COUNTER+1))
      if [ $COUNTER -ge $MAX_TRIES ]; then
        echo "[$(date +%H:%M:%S)]: Timed out waiting for Fleet service to start."
        echo "[$(date +%H:%M:%S)]: Check service status with: systemctl status fleet"
        return 1
      fi
      echo "[$(date +%H:%M:%S)]: Waiting for fleet service... ($COUNTER/$MAX_TRIES)"
      sleep 5
    done

    echo "[$(date +%H:%M:%S)]: Configuring fleetctl..."
    # Verify fleetctl is available and in PATH
    if ! command -v fleetctl &> /dev/null; then
      echo "[$(date +%H:%M:%S)]: ERROR: fleetctl command not found after installation!"
      echo "[$(date +%H:%M:%S)]: Manually setting PATH to include /usr/local/bin"
      export PATH=$PATH:/usr/local/bin
    fi

    # Use absolute path to fleetctl to avoid PATH issues
    /usr/local/bin/fleetctl config set --address https://192.168.57.105:8412
    /usr/local/bin/fleetctl config set --tls-skip-verify true
    /usr/local/bin/fleetctl setup --email admin@detectionlab.network --name admin --password 'Fl33tpassword!' --org-name DetectionLab
    /usr/local/bin/fleetctl login --email admin@detectionlab.network --password 'Fl33tpassword!'

    # Set the enrollment secret to match what we deploy to Windows hosts
    echo "[$(date +%H:%M:%S)]: Setting enrollment secret..."
    if mysql -uroot --password=fleet -e 'use fleet; INSERT INTO enroll_secrets(created_at, secret, team_id) VALUES ("2022-05-30 21:20:23", "enrollmentsecretenrollmentsecret", NULL);'; then
      echo "[$(date +%H:%M:%S)]: Updated enrollment secret"
    else
      echo "[$(date +%H:%M:%S)]: Error adding the custom enrollment secret. This is going to cause problems with agent enrollment."
    fi

    # Change the query intervals to reflect a lab environment
    echo "[$(date +%H:%M:%S)]: Updating query intervals..."
    # Every hour -> Every 3 minutes
    # Every 24 hours -> Every 15 minutes
    cd /opt || exit 1
    sed -i 's/interval: 3600/interval: 300/g' osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    sed -i 's/interval: 3600/interval: 300/g' osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    sed -i 's/interval: 28800/interval: 1800/g' osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    sed -i 's/interval: 28800/interval: 1800/g' osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    sed -i 's/interval: 0/interval: 1800/g' osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    sed -i 's/interval: 0/interval: 1800/g' osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml

    # Don't log osquery INFO messages
    # Fix snapshot event formatting
    echo "[$(date +%H:%M:%S)]: Setting up Fleet configuration..."
    # Get the configuration
    /usr/local/bin/fleetctl get config >/tmp/config.yaml
    
    # Fix the yq command for Ubuntu 24.04
    # In newer yq versions, -i needs to be combined with -y
    /usr/bin/yq -yi '.spec.agent_options.config.options.enroll_secret = "enrollmentsecretenrollmentsecret"' /tmp/config.yaml
    /usr/bin/yq -yi '.spec.agent_options.config.options.logger_snapshot_event_type = true' /tmp/config.yaml
    /usr/local/bin/fleetctl apply -f /tmp/config.yaml

    # Use fleetctl to import YAML files
    echo "[$(date +%H:%M:%S)]: Importing osquery configurations..."
    /usr/local/bin/fleetctl apply -f osquery-configuration/Fleet/Endpoints/MacOS/osquery.yaml
    /usr/local/bin/fleetctl apply -f osquery-configuration/Fleet/Endpoints/Windows/osquery.yaml
    for pack in osquery-configuration/Fleet/Endpoints/packs/*.yaml; do
      /usr/local/bin/fleetctl apply -f "$pack"
    done

    # Add Splunk monitors for Fleet
    # Files must exist before splunk will add a monitor
    touch /var/log/fleet/osquery_result
    touch /var/log/fleet/osquery_status
    
    echo "[$(date +%H:%M:%S)]: Fleet installation and configuration complete!"
  fi
}

install_velociraptor() {
  echo "[$(date +%H:%M:%S)]: Installing Velociraptor..."
  if [ ! -d "/opt/velociraptor" ]; then
    mkdir /opt/velociraptor || echo "Dir already exists"
  fi
  echo "[$(date +%H:%M:%S)]: Attempting to determine the URL for the latest release of Velociraptor"
  LATEST_VELOCIRAPTOR_LINUX_URL=$(curl -sL https://github.com/Velocidex/velociraptor/releases/ | grep linux-amd64 | grep href | head -1 | cut -d '"' -f 2 | sed 's#^#https://github.com#g')
  echo "[$(date +%H:%M:%S)]: The URL for the latest release was extracted as $LATEST_VELOCIRAPTOR_LINUX_URL"
  echo "[$(date +%H:%M:%S)]: Attempting to download..."
  wget -P /opt/velociraptor --progress=bar:force "$LATEST_VELOCIRAPTOR_LINUX_URL"
  if [ "$(file /opt/velociraptor/velociraptor*linux-amd64 | grep -c 'ELF 64-bit LSB executable')" -eq 1 ]; then
    echo "[$(date +%H:%M:%S)]: Velociraptor successfully downloaded!"
  else
    echo "[$(date +%H:%M:%S)]: Failed to download the latest version of Velociraptor. Please open a DetectionLab issue on Github."
    return
  fi

  cd /opt/velociraptor || exit 1
  mv velociraptor-*-linux-amd64 velociraptor
  chmod +x velociraptor
  # Generate a fresh server config with valid certificates and correct bindings
  echo "[$(date +%H:%M:%S)]: Generating Velociraptor server configuration..."
  mkdir -p /etc/velociraptor /opt/velociraptor/logs
  IP=$(ip -4 addr show eth1 | awk '/inet / {split($2,a,"/"); print a[1]}' | head -1)
  [ -z "$IP" ] && IP=192.168.57.105
  cat > /tmp/vr_merge.json << VRJSON
{
  "GUI": {"bind_address": "0.0.0.0", "bind_port": 9999, "public_url": "https://$IP:9999/app/index.html"},
  "Frontend": {"hostname": "logger", "bind_address": "0.0.0.0", "bind_port": 9000},
  "Client": {"server_urls": ["https://$IP:9000/"], "use_self_signed_ssl": true, "pinned_server_name": "VelociraptorServer"},
  "Datastore": {"location": "/opt/velociraptor", "filestore_directory": "/opt/velociraptor"},
  "Logging": {"output_directory": "/opt/velociraptor/logs"}
}
VRJSON
  ./velociraptor config generate --merge_file /tmp/vr_merge.json > /etc/velociraptor/server.config.yaml

  echo "[$(date +%H:%M:%S)]: Creating Velociraptor dpkg..."
  ./velociraptor --config /etc/velociraptor/server.config.yaml debian server
  echo "[$(date +%H:%M:%S)]: Cleanup velociraptor package building leftovers..."
  rm -rf /opt/velociraptor/logs
  echo "[$(date +%H:%M:%S)]: Installing the dpkg..."
  if dpkg -i velociraptor*server*.deb >/dev/null; then
    echo "[$(date +%H:%M:%S)]: Installation complete!"
    # Ensure correct permissions for the service user
    if id velociraptor >/dev/null 2>&1; then
      chown root:velociraptor /etc/velociraptor/server.config.yaml || true
      chmod 640 /etc/velociraptor/server.config.yaml || true
      chown -R velociraptor:velociraptor /opt/velociraptor || true
    fi

    systemctl daemon-reload
    # Prefer the packaged server unit
    VR_UNIT="velociraptor_server"
    if ! systemctl list-unit-files | grep -qi '^velociraptor_server\.service'; then VR_UNIT="velociraptor"; fi

    systemctl enable "$VR_UNIT" 2>/dev/null || true
    systemctl restart "$VR_UNIT" 2>/dev/null || systemctl start "$VR_UNIT" 2>/dev/null || true

    # Allow port 9999 if UFW is active
    if command -v ufw >/dev/null 2>&1; then
      if ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow 9999/tcp || true
      fi
    fi

    # Wait for GUI to listen on 9999
    echo "[$(date +%H:%M:%S)]: Waiting for Velociraptor GUI on :9999..."
    for i in $(seq 1 20); do
      if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":9999$"; then
        echo "[$(date +%H:%M:%S)]: Velociraptor is listening on port 9999."
        break
      fi
      sleep 3
    done
    # Ensure fallback unit is disabled if present
    systemctl disable --now velociraptor-standalone.service 2>/dev/null || true
    rm -f /etc/systemd/system/velociraptor-standalone.service
    systemctl daemon-reload
  else
    echo "[$(date +%H:%M:%S)]: Failed to install the dpkg"
    return
  fi
}

install_suricata() {
  # Run iwr -Uri testmyids.com -UserAgent "BlackSun" in Powershell to generate test alerts from Windows
  echo "[$(date +%H:%M:%S)]: Installing Suricata..."

  # Install suricata - already installed in apt_install_prerequisites
  test_suricata_prerequisites
  
  # Install suricata-update (available as a package in Ubuntu 24.04)
  echo "[$(date +%H:%M:%S)]: Installing suricata-update from package repository..."
  apt-get install -y python3-suricata-update

  cp /vagrant/resources/suricata/suricata.yaml /etc/suricata/suricata.yaml
  # Configure Suricata to monitor eth1
  mkdir -p /etc/suricata/suricata.d
  echo "SURICATA_OPTIONS=\"-i eth1\"" > /etc/default/suricata
  
  # Update suricata signature sources
  echo "[$(date +%H:%M:%S)]: Updating Suricata rules..."
  suricata-update update-sources
  # disable protocol decode as it is duplicative of Zeek
  echo re:protocol-command-decode >>/etc/suricata/disable.conf
  # enable et-open source
  suricata-update enable-source et/open

  # Update suricata and restart
  suricata-update
  systemctl stop suricata
  systemctl start suricata
  sleep 3

  # Verify that Suricata is running
  if ! pgrep -f suricata >/dev/null; then
    echo "Suricata attempted to start but is not running. Exiting"
    exit 1
  fi

  # Configure a logrotate policy for Suricata
  cat >/etc/logrotate.d/suricata <<EOF
/var/log/suricata/*.log /var/log/suricata/*.json
{
    hourly
    rotate 0
    missingok
    nocompress
    size=500M
    sharedscripts
    postrotate
            /bin/kill -HUP \`cat /var/run/suricata.pid 2>/dev/null\` 2>/dev/null || true
    endscript
}
EOF
}

test_suricata_prerequisites() {
  for package in suricata crudini; do
    echo "[$(date +%H:%M:%S)]: [TEST] Validating that $package is correctly installed..."
    # Use dpkg -l to check if package is installed
    if ! dpkg -l | grep -q "^ii.*$package"; then
      echo "[-] $package was not found. Attempting to reinstall."
      apt-get clean && apt-get -qq update && apt-get install -y $package
      if ! dpkg -l | grep -q "^ii.*$package"; then
        echo "[X] Unable to install $package even after a retry. Exiting."
        exit 1
      fi
    else
      echo "[+] $package was successfully installed!"
    fi
  done
}

install_zeek() {
  echo "[$(date +%H:%M:%S)]: Installing Zeek..."
  
  # Add Zeek repository for Ubuntu 24.04
  echo "[$(date +%H:%M:%S)]: Adding Zeek repository..."
  
  # Install required dependencies
  apt-get install -y gnupg2 curl
  
  # Add Zeek repository for Ubuntu (now maintained by Corelight)
  echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list
  curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
  
  # Update package list
  apt-get update
  
  # Install Zeek package
  echo "[$(date +%H:%M:%S)]: Installing Zeek package..."
  apt-get install -y zeek
  
  # Verify Zeek installation
  if [ ! -d "/opt/zeek" ]; then
    echo "[$(date +%H:%M:%S)]: ERROR: Zeek installation failed, directory /opt/zeek not found."
    exit 1
  fi
  
  # Configure PATH for Zeek
  export PATH=$PATH:/opt/zeek/bin
  
  # Create a Python virtual environment for Zeek tools
  echo "[$(date +%H:%M:%S)]: Setting up Python virtual environment for Zeek tools..."
  apt-get install -y python3-venv
  python3 -m venv /opt/zeek/venv
  
  # Install zkg in the virtual environment
  echo "[$(date +%H:%M:%S)]: Installing zkg in virtual environment..."
  /opt/zeek/venv/bin/pip install zkg
  
  # Configure zkg
  echo "[$(date +%H:%M:%S)]: Configuring zkg..."
  /opt/zeek/venv/bin/zkg refresh
  /opt/zeek/venv/bin/zkg autoconfig
  
  # Install ja3 package
  echo "[$(date +%H:%M:%S)]: Installing Zeek packages..."
  /opt/zeek/venv/bin/zkg install --force salesforce/ja3
  
  # Add virtual environment to path
  echo 'export PATH=$PATH:/opt/zeek/bin:/opt/zeek/venv/bin' >> /etc/profile.d/zeek.sh
  source /etc/profile.d/zeek.sh
  
  # Load Zeek scripts
  echo "[$(date +%H:%M:%S)]: Configuring Zeek scripts..."
  mkdir -p /opt/zeek/share/zeek/site/
  
  # Make sure the local.zeek file exists
  touch /opt/zeek/share/zeek/site/local.zeek
  
  echo '
  @load protocols/ftp/software
  @load protocols/smtp/software
  @load protocols/ssh/software
  @load protocols/http/software
  @load tuning/json-logs
  @load policy/integration/collective-intel
  @load policy/frameworks/intel/do_notice
  @load frameworks/intel/seen
  @load frameworks/intel/do_notice
  @load frameworks/files/hash-all-files
  @load base/protocols/smb
  @load policy/protocols/conn/vlan-logging
  @load policy/protocols/conn/mac-logging
  @load ja3

  redef Intel::read_files += {
    "/opt/zeek/etc/intel.dat"
  };
  
  redef ignore_checksums = T;
  ' >> /opt/zeek/share/zeek/site/local.zeek

  # Create Zeek configuration directory if it doesn't exist
  mkdir -p /opt/zeek/etc
  
  # Create a basic node.cfg file
  echo "[$(date +%H:%M:%S)]: Creating Zeek node configuration..."
  cat > /opt/zeek/etc/node.cfg << EOF
[manager]
type=manager
host=localhost

[proxy]
type=proxy
host=localhost

[worker-eth1]
type=worker
host=localhost
interface=eth1
EOF

  # Setup Zeek service - update for systemd
  echo "[$(date +%H:%M:%S)]: Creating Zeek systemd service..."
  cat > /etc/systemd/system/zeek.service <<EOF
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
Type=forking
ExecStart=/opt/zeek/bin/zeekctl start
ExecStop=/opt/zeek/bin/zeekctl stop
ExecReload=/opt/zeek/bin/zeekctl reload
RestartSec=10s
Restart=on-failure
User=root
Group=root
Environment="PATH=/opt/zeek/bin:/opt/zeek/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

[Install]
WantedBy=multi-user.target
EOF

  # Initialize Zeek
  echo "[$(date +%H:%M:%S)]: Initializing Zeek control framework..."
  /opt/zeek/bin/zeekctl install

  systemctl daemon-reload
  systemctl enable zeek
  systemctl start zeek
  sleep 5

  # Verify that Zeek is running
  if ! pgrep -f zeek >/dev/null; then
    echo "[$(date +%H:%M:%S)]: Zeek attempted to start but is not running. Check logs with 'journalctl -xeu zeek.service'"
    # Don't exit yet, let's try to get more diagnostics
    journalctl -xeu zeek.service
    echo "[$(date +%H:%M:%S)]: Zeek installation failed but continuing with other components"
  else
    echo "[$(date +%H:%M:%S)]: Zeek is running successfully!"
  fi
}
install_guacamole() {
  echo "[$(date +%H:%M:%S)]: Setting up Guacamole..."

  # Create the directory if it doesn't exist
  if [ ! -d "/opt/guacamole" ]; then
    mkdir /opt/guacamole || echo "Directory already exists"
  fi
  cd /opt/guacamole || exit 1

  echo "[$(date +%H:%M:%S)]: Downloading Guacamole server version 1.5.5..."
  wget --progress=bar:force "https://apache.org/dyn/closer.lua/guacamole/1.5.5/source/guacamole-server-1.5.5.tar.gz?action=download" -O guacamole-server.tar.gz

  if [ $? -ne 0 ]; then
    echo "[-] Failed to download Guacamole server. Exiting."
    exit 1
  fi

  tar -xf guacamole-server.tar.gz && cd "guacamole-server-1.5.5" || { echo "[-] Unable to find the Guacamole folder."; exit 1; }

  echo "[$(date +%H:%M:%S)]: Configuring and installing Guacamole server..."
  if ./configure --with-init-dir=/etc/init.d --disable-Werror && make --quiet && make --quiet install; then
    echo "[$(date +%H:%M:%S)]: Guacamole server successfully configured and installed!"
  else
    echo "[-] An error occurred while installing Guacamole."
    exit 1
  fi
  ldconfig

  # In Ubuntu 24.04, tomcat10 is used instead of tomcat9
  cd /var/lib/tomcat10/webapps || { echo "[-] Unable to find the tomcat10/webapps folder."; exit 1; }

  echo "[$(date +%H:%M:%S)]: Downloading Guacamole web application version 1.5.5..."
  wget --progress=bar:force "https://apache.org/dyn/closer.lua/guacamole/1.5.5/binary/guacamole-1.5.5.war?action=download" -O guacamole.war

  if [ $? -ne 0 ]; then
    echo "[-] Failed to download Guacamole web application. Exiting."
    exit 1
  fi

  mkdir -p /etc/guacamole/shares
  chmod 777 /etc/guacamole/shares
  mkdir -p /usr/share/tomcat10/.guacamole

  echo "[$(date +%H:%M:%S)]: Copying configuration files..."
  cp /vagrant/resources/guacamole/user-mapping.xml /etc/guacamole/
  cp /vagrant/resources/guacamole/guacamole.properties /etc/guacamole/
  cp /vagrant/resources/guacamole/guacd.service /lib/systemd/system
  
  # Ensure GUACAMOLE_HOME and required extensions are in place
  mkdir -p /etc/guacamole/extensions /etc/guacamole/lib
  # Install auth-file extension via Maven Central to match the webapp version
  GUAC_VER="1.5.5"
  echo "[$(date +%H:%M:%S)]: Installing Guacamole auth-file extension ($GUAC_VER) from Maven Central..."
  AUTH_JAR_URL="https://repo1.maven.org/maven2/org/apache/guacamole/guacamole-auth-file/${GUAC_VER}/guacamole-auth-file-${GUAC_VER}.jar"
  curl -fsSL "$AUTH_JAR_URL" -o "/etc/guacamole/extensions/guacamole-auth-file-${GUAC_VER}.jar" || true

  # Install Jakarta EE migration tool and migrate the WAR for Tomcat 10
  echo "[$(date +%H:%M:%S)]: Installing Tomcat Jakarta migration tool and migrating guacamole.war..."
  apt-get install -y tomcat-jakartaee-migration >/dev/null 2>&1 || true
  if command -v javax2jakarta >/dev/null 2>&1; then
    ( cd /var/lib/tomcat10/webapps && cp -f guacamole.war guacamole-orig.war && javax2jakarta guacamole.war guacamole-jakarta.war && mv -f guacamole-jakarta.war guacamole.war ) || true
  fi

  # Set GUACAMOLE_HOME for tomcat10 via a systemd drop-in
  mkdir -p /etc/systemd/system/tomcat10.service.d
  cat > /etc/systemd/system/tomcat10.service.d/guacamole.conf <<EOF
[Service]
Environment=GUACAMOLE_HOME=/etc/guacamole
EOF

  # Update paths for tomcat10
  ln -s /etc/guacamole/guacamole.properties /usr/share/tomcat10/.guacamole/
  ln -s /etc/guacamole/user-mapping.xml /usr/share/tomcat10/.guacamole/

  echo "[$(date +%H:%M:%S)]: Setting up guacd user..."
  useradd -M -d /var/lib/guacd/ -r -s /sbin/nologin -c "Guacd User" guacd || echo "Guacd user already exists"
  mkdir -p /var/lib/guacd
  chown -R guacd: /var/lib/guacd

  echo "[$(date +%H:%M:%S)]: Enabling and starting services..."
  systemctl daemon-reload
  systemctl enable guacd
  systemctl enable tomcat10
  systemctl start guacd
  systemctl restart tomcat10

  if systemctl is-active --quiet guacd && systemctl is-active --quiet tomcat10; then
    echo "[$(date +%H:%M:%S)]: Guacamole installation complete!"
  else
    echo "[-] An error occurred while starting services."
    systemctl status guacd
    systemctl status tomcat10
    exit 1
  fi
}

configure_splunk_inputs() {
  echo "[$(date +%H:%M:%S)]: Configuring Splunk Inputs..."
  # Suricata
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata index suricata
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata sourcetype suricata:json
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata whitelist 'eve.json'
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata disabled 0
  crudini --set /opt/splunk/etc/apps/search/local/props.conf suricata:json TRUNCATE 0

  # Fleet
  /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_result" -index osquery -sourcetype 'osquery:json' -auth 'admin:changeme' --accept-license --answer-yes --no-prompt
  /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_status" -index osquery-status -sourcetype 'osquery:status' -auth 'admin:changeme' --accept-license --answer-yes --no-prompt

  # Zeek - using direct file method instead of crudini to avoid escape issues
  mkdir -p /opt/splunk/etc/apps/Splunk_TA_bro/local
  cat > /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf << EOF
[monitor:///opt/zeek/spool/manager]
index = zeek
sourcetype = zeek:json
whitelist = .*\.log$
blacklist = .*communication\.log$|.*stderr\.log$
disabled = 0
EOF

  # Ensure permissions are correct and restart splunk
  chown -R splunk:splunk /opt/splunk/etc/apps/Splunk_TA_bro
  /opt/splunk/bin/splunk restart
}

main() {
  configure_dns
  apt_install_prerequisites
  modify_motd
  test_prerequisites
  fix_eth1_static_ip
  install_splunk
  download_palantir_osquery_config
  install_fleet_import_osquery_config
  install_velociraptor
  install_suricata
  install_zeek
  install_guacamole
  configure_splunk_inputs
}

splunk_only() {
  install_splunk
  configure_splunk_inputs
}

velociraptor_only() {
  install_velociraptor
}

# Allow custom modes via CLI args
if [ -n "$1" ]; then
  eval "$1"
else
  main
fi
exit 0