FROM openjdk:slim
COPY . /sources
WORKDIR /sources
RUN ./mvnw clean package \
 && rm -fr ${HOME}/.m2 \
 && mkdir -p /opt/app \
 && mv target/*.jar /opt/app/app.jar \
 && mv /sources/src/docker/wait-for-it.sh /opt/app/. \
 && apt update && apt install curl jq -y \
 && chmod +x /opt/app/wait-for-it.sh

CMD java -jar /opt/app/app.jar