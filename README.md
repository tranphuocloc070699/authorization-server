
# Authorization server with SSO features
Real world Authorization server to hand on Single Sign On
## Demo
Video
## Technologies
- Spring Security + OAuth2
- Thymeleaf + RestfulAPI
- Spring Data Jpa
- Spring Boot Mail
- Multi Factor Authenticate (Google Authenticator App)
- Redis
- RabbitMQ
## Diagram

## Running local
1. Clone the project
```
git clone https://github.com/tranphuocloc070699/authorization-server
```
2. Run Postgresql with docker
```
docker run --name your-pg-container -e POSTGRES_USER=your-pg-username -e POSTGRES_PASSWORD=your-pg-password -p 5432:5432 -v db:/var/lib/postgresql/data -d postgres
```
3. Create your database inside postgres container
```
docker exec your-pg-container createdb -U your-pg-username your-database-you-want-to-create
```
4. Run Redis with Docker
```
docker run --name redis-server -p 6379:6379 -d redis:latest
```
5. Run RabbitMQ with Docker
```
docker run --name rabbitmq-server -p 5672:5672 -p 15672:15672 -d rabbitmq:management
```

6. Rename ``application.properties.example`` file to ``application.properties``

7. Add properties's value to ``application.properties`` file
```
	 spring.datasource.url=jdbc:postgresql://localhost:5432/your-database-you-created
	 spring.datasource.username=your-pg-username
	 spring.datasource.password=your-pg-password
	 spring.security.oauth2.client.registration.google.client-id=
	 spring.security.oauth2.client.registration.google.client-secret=
	 spring.mail.username=your-gmail-account
	 spring.mail.password=your-gmail-password
```
How to get google client-id and secret?[Click Here](https://www.youtube.com/watch?v=OKMgyF5ezFs)

How to get gmail-password? [Click Here](https://www.youtube.com/watch?v=OdQ3GyBsdAA) (18:50 -> 21:33)

8. Run project on IDE
## Running with docker
1. Clone the project
```
git clone https://github.com/tranphuocloc070699/authorization-server
```
2. navigate to project
```
cd ./authorization-server
```
3. run docker compose
```
docker compose up
```
4. Access ``http://localhost:8080``

