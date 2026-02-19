FROM alpine:3.20

RUN apk add --no-cache bash postgresql16-client tzdata

WORKDIR /backup

COPY backup.sh /backup/backup.sh
COPY crontab /backup/crontab

RUN chmod +x /backup/backup.sh

CMD ["/usr/sbin/crond", "-f", "-l", "2", "-L", "/var/log/cron.log", "-c", "/backup"]
