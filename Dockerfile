FROM frolvlad/alpine-oraclejdk8:slim
VOLUME /tmp
ADD ./complete/build/libs/gs-pseudoRandomOracle-service-0.1.0.jar app.jar
ENV JAVA_OPTS=""
EXPOSE 8080
ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar /app.jar" ]

