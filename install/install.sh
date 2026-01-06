#!/usr/bin/env bash

add_line_if_missing() {
    local LINE="$1"
    local FILE="$2"

    # create file if it doesn't exist
    [ -f "$FILE" ] || touch "$FILE"

    # check if line exists
    if ! grep -Fxq "$LINE" "$FILE"; then
        echo "$LINE" >> "$FILE"
        echo "Added line to $FILE"
    fi
}

add_redis_path() {
    local REDIS_PATH="/redis-stable/src"
    local LINE="export PATH=\"\$PATH:$REDIS_PATH\""

    # detect original user
    local USER
    if [ -n "$SUDO_USER" ]; then
        USER="$SUDO_USER"
    else
        USER=$(whoami)
    fi

    local USER_HOME
    USER_HOME=$(eval echo "~$USER")

    # detect user's shell
    local USER_SHELL
    USER_SHELL=$(getent passwd "$USER" | cut -d: -f7)
    [ -z "$USER_SHELL" ] && USER_SHELL="$SHELL"

    # pick RC file
    local RC
    if [[ $USER_SHELL == *"zsh" ]]; then
        RC="$USER_HOME/.zshrc"
    else
        RC="$USER_HOME/.bashrc"
    fi

    # add to RC file if missing
    add_line_if_missing "$LINE" "$RC"

    # add to current session if not already in PATH
    case ":$PATH:" in
        *":$REDIS_PATH:"*)
            ;;  # already in PATH
        *)
            export PATH="$PATH:$REDIS_PATH"
            ;;
    esac

    echo "Redis path added to RC ($RC) and current session"
}


print_green() {
  # Prints text in green color
    echo "[+] \e[32m$1\e[0m\n"
}

exit_on_cmd_failure() {
  if [ $? -ne 0 ]; then
      echo "Problem installing Slips. Aborting."
      exit 1
  fi
}



# Function to check if zeek or bro is available
check_zeek_or_bro() {
    if which zeek > /dev/null 2>&1 || which bro > /dev/null 2>&1; then
        return 0 # Indicate success (found)
    else
        return 1 # Indicate failure (not found)
    fi
}



# to disable prompts
export DEBIAN_FRONTEND=noninteractive

print_green "Setting up local timezone"

ln -snf /usr/share/zoneinfo/$TZ /etc/localtime
echo $TZ > /etc/timezone

exit_on_cmd_failure

print_green "Running apt update"
sudo apt-get update

exit_on_cmd_failure

print_green "Installing Slips dependencies ..."
 sudo apt-get install  -y --no-install-recommends \
    cmake \
    make \
    gcc\
    g++ \
    flex \
    bison \
    libpcap-dev \
    libssl-dev \
    swig \
    zlib1g-dev \
    wget \
    ca-certificates \
    git \
    curl \
    gnupg \
    lsb-release \
    software-properties-common \
    build-essential \
    file \
    lsof \
    iptables \
    iproute2 \
    nfdump \
    tshark \
    whois \
    yara \
    net-tools \
    vim \
    less \
    unzip \
    python3-certifi \
    python3-dev \
    python3-tzlocal \
    python3-pip \
    golang \
    notify-osd \
    libnotify-bin \
    net-tools \
    lsb-release


exit_on_cmd_failure

if ! check_zeek_or_bro; then
  print_green "Installing Zeek"
  UBUNTU_VERSION=$(lsb_release -r | awk '{print $2}')
  ZEEK_REPO_URL="download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VERSION}"

  # Add the repository to the sources list
  sudo echo "deb http://${ZEEK_REPO_URL}/ /" | sudo tee /etc/apt/sources.list.d/security:zeek.list \
  && curl -fsSL "https://${ZEEK_REPO_URL}/Release.key" | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
  && sudo apt update && sudo apt install -y --no-install-recommends --fix-missing zeek-8.0

  # create a symlink to zeek so that slips can find it
  sudo ln -s /opt/zeek/bin/zeek /usr/local/bin/bro
  export PATH=$PATH:/usr/local/zeek/bin
  echo "export PATH=$PATH:/usr/local/zeek/bin" >> ~/.bashrc

  # dont continue with slips installation if zeek isn't installed
  if ! check_zeek_or_bro; then
    echo "Problem installing Slips. Aborting."
    exit 1
  fi
fi


print_green "Installing Redis"
curl -L https://download.redis.io/redis-stable.tar.gz -o /tmp/redis-stable.tar.gz \
    && mkdir -p /redis-stable \
    && tar xzf redis-stable.tar.gz -C / \
    && cd /redis-stable \
    && make distclean \
    && make MALLOC=libc

add_redis_path


exit_on_cmd_failure

print_green "Installing Python requirements"

python3 -m pip install --upgrade pip \
&& pip3 install --ignore-installed -r install/requirements.txt \
&& pip3 install --ignore-installed six

exit_on_cmd_failure


# For Kalipso
print_green "Installing nodejs and npm dependencies"
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | sudo bash - \
    && export NVM_DIR="$HOME/.nvm" \
    && [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" \
    && nvm install 22 \
    && cd modules/kalipso && npm install \
    && cd ../..

exit_on_cmd_failure


print_green "Installing p2p4slips"
# build the pigeon and Add pigeon to path
git submodule init && git submodule update && cd p2p4slips && go build && export PATH=$PATH:$(pwd) >> ~/.bashrc && cd ..

exit_on_cmd_failure

# running slips for the first time
print_green "Executing 'redis-server --daemonize yes'"
redis-server --daemonize yes

exit_on_cmd_failure

print_green "Successfully installed Slips."
