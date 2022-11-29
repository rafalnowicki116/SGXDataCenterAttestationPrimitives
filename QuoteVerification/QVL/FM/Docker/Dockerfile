FROM ubuntu:18.04
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Warsaw
RUN         apt-get update \
                && apt-get install -y \
                    software-properties-common \
                    wget \
                && add-apt-repository -y ppa:ubuntu-toolchain-r/test \
                && apt-get update \
                && apt-get install -y \
                    make \
                    git \
                    curl \
                    vim \
                    vim-gnome \
                    wget \
		&& apt-get install -y \
		   gcc-4.8 g++-4.8 gcc-4.8-base \
           gcc g++ build-essential \ 
           libssl-dev
RUN mkdir CMAKE
RUN cd CMAKE
RUN wget http://www.cmake.org/files/v3.16/cmake-3.16.0.tar.gz \
    && tar xf cmake-3.16.0.tar.gz \
    && cd cmake-3.16.0 \
    && ./configure \
    && make \
    && make install

RUN apt install -y gcc-7-powerpc-linux-gnu g++-7-powerpc-linux-gnu

RUN mkdir /OpenSSL \
    && cd /OpenSSL \
    && wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1j.tar.gz \
    && tar -xf openssl-1.1.1j.tar.gz \
    && cd ./openssl-1.1.1j \
    && ./Configure linux-generic32 -DL_ENDIAN \
    && make CC=powerpc-linux-gnu-gcc-7 RANLIB=powerpc-linux-gnu-ranlib LD=powerpc-linux-gnu-ld MAKEDEPPROG=powerpc-linux-gnu-gcc-7 PROCESSOR=ARM




