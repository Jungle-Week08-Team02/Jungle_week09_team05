# Ubuntu 18.04 이미지를 x86 아키텍처로 명시
FROM --platform=linux/amd64 ubuntu:18.04

# apt 패키지 목록 업데이트 및 기본 패키지 설치
RUN apt-get update && apt-get install -y \
    ufw \
    curl \
    vim \
    git \
    sudo \
    net-tools \
    iputils-ping \
    locales \
    # Pintos 개발에 필요한 추가 패키지들
    build-essential \
    gdb \
    qemu \
    qemu-system-x86 \
    python3 \
    gcc-multilib \
    # ssh 연결에 필요한 추가 패키지
    openssh-server \
    && apt-get clean

# 사용자 추가 및 sudo 권한 부여
RUN useradd -ms /bin/bash ubuntu && adduser ubuntu sudo

# sudo 사용시 패스워드 없이 사용할 수 있도록 설정 (선택사항)
RUN echo "ubuntu ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# SSH 설정
RUN mkdir /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# root 비밀번호 변경
RUN echo "root:1q2w3e4r!" | chpasswd

# 사용자 비밀번호 변경
RUN echo "ubuntu:1q2w3e!" | chpasswd

# SSH 포트 노출
EXPOSE 22

# 홈 디렉토리로 워킹 디렉토리 설정
WORKDIR /home/ubuntu

# 컨테이너 시작 시 SSH 서비스 실행
CMD ["/usr/sbin/sshd", "-D"]