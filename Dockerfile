FROM ubuntu:latest
RUN apt-get update && apt-get install -y \
	curl

ADD scripts/install_go.sh /tmp/install_go.sh
RUN /bin/bash -c /tmp/install_go.sh && \
    rm /tmp/install_go.sh

RUN apt-get install -y clang llvm

ENV BPF_CLANG="clang"
ENV BPF_CFLAGS="-O2 -g -Wall -Werror"
ENV PATH="${PATH}:/usr/local/go/bin:/go/bin"
