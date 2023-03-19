# Stage 1: Build the application
FROM maven:3.6.3-openjdk-17 as build
COPY src /usr/home/auth-service/src
COPY ./pom.xml /usr/home/auth-service
RUN mvn -f /usr/home/auth-service/pom.xml clean package -DskipTests

# Stage 2: Package the application
FROM openjdk:17-jdk
COPY --from=build /usr/home/auth-service/target/*.jar /auth-service.jar
EXPOSE 8082
ENTRYPOINT ["java","-jar","/auth-service.jar"]