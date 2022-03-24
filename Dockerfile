FROM alpine:latest
RUN apk add sudo
WORKDIR /app
COPY pingscan/pingscan .
ENV CIDR=172.17.0.0/24
CMD  sudo ./pingscan -cidr=$CIDR -dev=eth0 -timeout=10 -ouifile=pingscan/ieee-oui.txt  
