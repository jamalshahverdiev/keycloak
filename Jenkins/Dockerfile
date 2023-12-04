FROM jenkins/jenkins:lts
USER root
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt
USER jenkins
EXPOSE 8080

