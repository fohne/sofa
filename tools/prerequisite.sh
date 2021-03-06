#!/bin/bash
C_NONE="\033[0;00m"
C_GREEN="\033[1;32m"
C_RED_BK="\033[1;41m"
C_YELLOW="\033[1;93m"

WITH_SUDO=""
if [[ $(which sudo) ]]; then 
    echo -e "${C_GREEN}You are going to install SOFA with sudo${C_NONE}"
    WITH_SUDO="sudo" 
fi

# Detect OS distribution
# Try source all the release files
for file in /etc/*-release; do
    source $file 
done

if [[ "$NAME" != ""  ]]; then
    OS="$NAME"
    VERSION="$VERSION_ID"
elif [[ -f /etc/debian_version ]]; then
    # Older Debian/Ubuntu/etc.
    OS="Debian"
    VERSION="$(cat /etc/debian_version)"
else
    OS="$(lsb_release -si)"
    VERSION="$(lsb_release -sr)"
fi

function inform_sudo()
{
    if [[ $(which sudo) ]]; then 
        [[ ! -z "$1" ]] && echo "$1"
        # Exit without printing messages if password is still in the cache.
        sudo -n true 2> /dev/null
        [[ $? == 0 ]] && return 0;
        sudo >&2 echo -e "\033[1;33mRunning with root privilege now...\033[0;00m";
        [[ $? != 0 ]] && >&2 echo -e "\033[1;31mAbort\033[0m" && exit 1;
    fi
}

function install_python_packages()
{
    # Install Python packages
    echo -e "${C_GREEN}Installing python packages...${C_NONE}"
    source ~/.bashrc
    

    if [[ $(which yum) ]]  ; then
        $WITH_SUDO yum install -y epel-release
        $WITH_SUDO yum install -y https://centos7.iuscommunity.org/ius-release.rpm
        $WITH_SUDO yum install -y python36u python36u-pip python36u-devel
    elif [[ "${OS}" == "Ubuntu" ]] && ( [[ "${VERSION}" == "14.04"* ]] || [[ "${VERSION}" == "16.04"* ]] ) ; then	
        $WITH_SUDO apt-get install software-properties-common -y
        $WITH_SUDO add-apt-repository ppa:deadsnakes/ppa -y
        $WITH_SUDO apt-get update -y
        $WITH_SUDO apt-get install python3.6 python3.6-dev -y
	    curl https://bootstrap.pypa.io/get-pip.py > get-pip.py
	    $WITH_SUDO python3.6 get-pip.py
        $WITH_SUDO rm get-pip.py
    elif [[ $(which apt) ]] ; then	
        $WITH_SUDO apt install python3 python3-pip python3-dev -y
    else
	    file_pytar="Python-3.6.0.tar.xz"
	    wget https://www.python.org/ftp/python/3.6.0/$file_pytar
	    tar xJf $file_pytar
	    cd Python-3.6.0
	    ./configure --with-ssl
	    make -j
	    $WITH_SUDO make install
	    # Install for Python3
	    cd - 
	    rm -r Python-3.6.0*
    fi
    [[ $? != 0 ]] && echo -e "${C_RED_BK}Failed... :(${C_NONE}" && exit 1
    echo "Install via pip"
    PIP_PACKAGES="numpy pandas matplotlib grpcio scipy networkx cxxfilt fuzzywuzzy sqlalchemy sklearn python-Levenshtein"
    python3 -m pip install --user --upgrade pip
    python3 -m pip install --user --no-cache-dir ${PIP_PACKAGES}
    [[ $? != 0 ]] && echo -e "${C_RED_BK}Failed... :(${C_NONE}" && exit 1

    if [[ $(which /opt/conda/bin/python3.6) ]] ; then
        echo -e "${C_GREEN}Installing conda packages...${C_NONE}"
        /opt/conda/bin/python3.6 -m pip install --user --upgrade pip
        /opt/conda/bin/python3.6 -m pip install --user --no-cache-dir  ${PIP_PACKAGES}
        [[ $? != 0 ]] && echo -e "${C_RED_BK}Failed... :(${C_NONE}" && exit 1
    fi

}

function install_packages()
{
    echo -e "${C_GREEN}Installing other packages...${C_NONE}"

    #inform_$WITH_SUDO "Running $WITH_SUDO for installing packages"
    if [[ $(which apt) ]] ; then
        $WITH_SUDO apt-get update
        $WITH_SUDO apt-get update --fix-missing
	    $WITH_SUDO apt-get install -y curl wget make gcc g++ cmake \
            linux-tools-common tcpdump sysstat \
            linux-tools-$(uname -r) linux-cloud-tools-$(uname -r) linux-tools-generic linux-cloud-tools-generic \
            bpfcc-tools linux-headers-$(uname -r) ntp
	    [[ $? != 0 ]] && echo -e "${C_RED_BK}Failed... :(${C_NONE}" && exit 1
    elif [[ $(which yum) ]]  ; then
        $WITH_SUDO yum install -y epel-release 
        $WITH_SUDO yum install -y curl wget make gcc gcc-c++ cmake \
            perf tcpdump sysstat \
            centos-release-scl devtoolset-4-gcc* 
        [[ $? != 0 ]] && echo -e "${C_RED_BK}Failed... :(${C_NONE}" && exit 1
    else
        echo -e "${C_RED_BK}This script does not support your OS distribution, '$OS'. Please install the required packages by yourself. :(${C_NONE}"
    fi
}

function install_utility_from_source()
{
    echo -e "${C_GREEN}Installing utilities from source...${C_NONE}"
    #make -C sofa-pcm -j4 
    [[ $? != 0 ]] && echo -e "${C_RED_BK}Failed... :(${C_NONE}" && exit 1
    nvcc tools/cuhello.cu -o ./bin/cuhello
    [[ $? != 0 ]] && echo -e "${C_YELLOW}No nvcc found; nvcc is required to improve perf timestamp accuracy.${C_NONE}" 
    g++  tools/sofa_perf_timebase.cc -o ./bin/sofa_perf_timebase
    gcc  tools/real_mono_diff.c -o ./bin/real_mono_diff
    [[ $? != 0 ]] && echo -e "${C_RED_BK}Failed... :(${C_NONE}" && exit 1
    #rm -rf pcm
    #git clone https://github.com/opcm/pcm.git 
    #sed -i -- 's/-DPCM_USE_PERF//g' pcm/Makefile
    #cd pcm && make -j && cd - 
    #$WITH_SUDO mkdir -p /usr/local/intelpcm/bin 
    #$WITH_SUDO cp pcm/pcm-*.x /usr/local/intelpcm/bin 
    #
    #rm -r papi
    #if [[ ! -f papi-5.6.0.tar.gz ]]; then  
    #    wget http://icl.utk.edu/projects/papi/downloads/papi-5.6.0.tar.gz
    #fi
    #tar xvf papi-5.6.0.tar.gz
    #mv papi-5.6.0 papi
    #cd papi/src && ./configure --prefix=$(pwd)/build && make -j4 && make install && cd - 
    #rm papi-5.6.0.tar.gz
}

# main
echo -e "${C_GREEN}OS Distribution:${C_NONE} '$OS'"
echo -e "${C_GREEN}Version:${C_NONE} '$VERSION'"
printf "\n\n"

install_packages
install_python_packages
install_utility_from_source

echo -e "${C_GREEN}Complete!!${C_NONE}"
