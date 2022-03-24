FROM alpine:latest
RUN apk add sudo
WORKDIR /app
COPY pingscan/pingscan .
CMD [ "sudo", "./pingscan", "-cidr=172.17.0.0/24", "-dev=eth0", "-timeout=10", "-ouifile=pingscan/ieee-oui.txt " ]
