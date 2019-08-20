FROM debian:stretch

WORKDIR /home/

RUN apt-get -y update && apt-get -y install apt-transport-https \
                curl lsb-release gnupg

RUN echo "deb https://dl.bintray.com/wand/general $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
RUN echo "deb https://dl.bintray.com/wand/libtrace $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list


RUN curl --silent "https://bintray.com/user/downloadSubjectPublicKey?username=wand" | apt-key add -

RUN apt-get -y update && apt-get -y install \
                build-essential \
                autoconf \
                libtool \
                m4 \
                automake \
                git \
                iproute2 \
                libgoogle-perftools-dev \
                libpcap-dev \
                bison \
                flex \
                libtrace4-tools \
                libtrace4-dev \
                libjudy-dev \
                libosip2-dev \
                libyaml-dev \
                libzmq3-dev \
                libssl1.0-dev \
                systemd \
                procps \
                uthash-dev \
                rsyslog \
                vim \
                emacs \
                locate \
                gdb \
                valgrind

RUN mkdir /home/install
RUN mkdir /home/install/bin  
ENV PATH="/home/install/bin:${PATH}"
RUN echo "HISTCONTROL=ignoreboth" >> /root/.bashrc
RUN echo "HISTCONTROL=ignoreboth" >> /.bashrc
RUN echo  "/home/install/lib" >> /etc/ld.so.conf.d/libc.conf
RUN mkdir /etc/openli  

#COPY ./ .



