ARCH=`arch`
if [[ $ARCH = 'aarch64' ]]; then ARCH=arm64; fi

curl -L -O https://go.dev/dl/go1.19.4.linux-$ARCH.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf go1.19.4.linux-$ARCH.tar.gz
