# Spring Boot Secure API by OpenId Connect using Spring Security 

- [Spring Boot Secure API by OpenId Connect using Spring Security](#spring-boot-secure-api-by-openid-connect-using-spring-security)
  - [Description](#description)
  - [Prerequisite](#prerequisite)
  - [Run stack](#run-stack)
    - [Build application code and docker image](#build-application-code-and-docker-image)
    - [Run the application and the keycloak instance](#run-the-application-and-the-keycloak-instance)
    - [1. Check that the keycloak is up and runnning.](#1-check-that-the-keycloak-is-up-and-runnning)
    - [2. Check that application is up and running](#2-check-that-application-is-up-and-running)
  - [Test stack](#test-stack)
    - [1. Generate a JWT token :](#1-generate-a-jwt-token)
    - [2. Redirect to login page anonymous user](#2-redirect-to-login-page-anonymous-user)
    - [3. Role are respected](#3-role-are-respected)
      - [3.1 writer can read (user `test`)](#31-writer-can-read-user-test)
      - [3.2 reader can read (user `test2`)](#32-reader-can-read-user-test2)
      - [3.3 other roles can't read (user `test3`)](#33-other-roles-cant-read-user-test3)
      - [3.4 writer can write (user `test`)](#34-writer-can-write-user-test)
      - [3.5 other roles can't write (user `test2` and user `test3`)](#35-other-roles-cant-write-user-test2-and-user-test3)
    - [Code explanation](#code-explanation)
      - [1. Protect the application with an openid provider](#1-protect-the-application-with-an-openid-provider)
      - [2. Add authentification based on Authorization header](#2-add-authentification-based-on-authorization-header)
      - [3. modify default configuration](#3-modify-default-configuration)
      - [4. added authetification using cookie](#4-added-authetification-using-cookie)
    - [Reference Documentation](#reference-documentation)
    - [Launch into IDE](#launch-into-ide)
    - [TODO](#todo)



## Description

This is an exemple of Rest API were some endpoints are secured by an OpenId Connect
This application contains two endpoints
- `/` is a public endpoint
- `/api/private` is a private endpoint
  - this endpoint is callable using
    - `GET` verb : only authenticated user with `reader` or `writer` role can call.
    - `POST` verb : only authenticated user with `writer` role can call.

```Java
	@GetMapping("/")
	public String publicEndpoint() {
		return "Hello Public Ok";
	}
	
	@RolesAllowed({ "ROLE_reader", "ROLE_writer" })
	@GetMapping("/api/private")
	public Authentication privateEndpoint(Authentication authentication) {
		return authentication;
	}

	@RolesAllowed({ "ROLE_writer" })
	@PostMapping("/api/private")
	public String privateEndpointWrite() {
		return "done";
	}
```

For this excercice we are using `keycloak` as OpenId provider.
This exemple inclu preconfigured `keycloak` instance (h2 db is provided into `src/docker/keycloak.mv.db`). This instance contains
- a `organisation` realm
- a `client1` client inside the `organisation` realm
- two roles `reader` and `writer`
- three users with the same password `password` :
  - `test` having the `writer` role
  - `test2` having the `reader` role
  - `test3` without role

## Prerequisite

To use this app the following prerequisite are needed :
- docker 
- docker-compose
- openjdk

## Run stack

### Build application code and docker image
```bash
$ docker-compose -f src/docker/docker-compose.yml build
```

### Run the application and the keycloak instance

Run the following command to launch the application and the keycloak instance.
The `app` container will wait until keycloak start and will launch the java application.
```bash
$ docker-compose -f src/docker/docker-compose.yml up -d --force-recreate
$ docker-compose -f src/docker/docker-compose.yml logs -f
```

### 1. Check that the keycloak is up and runnning.
   - You should be able to access [The organisation realm here](http://localhost:8080/auth/admin/master/console/#/realms/organisation)
   - You should be able to access [The client1 client here](http://localhost:8080/auth/admin/master/console/#/realms/organisation/clients/0aa973e3-2222-4448-965f-30bd4ec343bc)
   - You should be able to access [The keycloak users page here](http://localhost:8080/auth/admin/master/console/#/realms/organisation/users). Click the `View all users` button to see users.
   - You should be able to access [The role mappings page here](http://localhost:8080/auth/admin/master/console/#/realms/organisation/users/680f0684-b324-4a5d-9e96-7b08d448d4cc/role-mappings) of the user having the login `test`. Click the `Client Roles` dropdown and tape `client1`. You should see that the user have only `writer` into `Assigned Roles` select.

### 2. Check that application is up and running

> Run the following command to have a shell inside the app container 

```bash
$ docker-compose -f src/docker/docker-compose.yml exec app bash

root@fff93b8266a1:/sources#
```

> Always inside the `app` container, run this command to test that the public endpoint is up and running.

```bash
$ curl "localhost:8081/" -s
Hello Public Ok
```
## Test stack

### 1. Generate a JWT token :

> Always inside the `app` container, using the following command generate a JWT token of the user `test`

```bash
$ curl -s -d 'client_id=client1' \
    -d 'client_secret=7926b321-48ef-4ba9-9c57-ee9c98de7dd6' \
    -d 'username=test' \
    -d 'password=password' \
    -d 'grant_type=password' \
    'http://keycloak:8080/auth/realms/organisation/protocol/openid-connect/token' \
    | jq .access_token -r
```

You can decode the generated token using [jwt.io web site](https://jwt.io/)

### 2. Redirect to login page anonymous user 
> Always inside the `app` container, run this command to test that the private endpoint is secured. Without bearer user is redirected to the keycloak login page.

```bash
$ curl "localhost:8081/api/private" -vL

< HTTP/1.1 302 
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Location: http://localhost:8081/oauth2/authorization/organisation
< Content-Length: 0
< Date: Sat, 18 Apr 2020 15:37:56 GMT
< 
* Connection #0 to host localhost left intact
* Issue another request to this URL: 'http://localhost:8081/oauth2/authorization/organisation'
* Found bundle for host localhost: 0x56357c93b980 [can pipeline]
* Could pipeline, but not asked to!
* Re-using existing connection! (#0) with host localhost
* Connected to localhost (127.0.0.1) port 8081 (#0)
* Expire in 0 ms for 6 (transfer 0x56357c940f50)
> GET /oauth2/authorization/organisation HTTP/1.1
> Host: localhost:8081
> User-Agent: curl/7.64.0
> Accept: */*
> 
< HTTP/1.1 302 
< Set-Cookie: JSESSIONID=FE73A1CFE7BBC8D92843240E2C14D54A; Path=/; HttpOnly
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Location: http://keycloak:8080/auth/realms/organisation/protocol/openid-connect/auth?response_type=code&client_id=client1&scope=openid%20profile%20email&state=Vursu6cdVMD0_xWBrOYbo-XnWc4Jfkf669IuCZB9jVw%3D&redirect_uri=http://localhost:8081/login/oauth2/code/organisation&nonce=AfbDVJTZ4TXsdbQilshIx4IzlhW5IwJPnQkr6je1zFI
< Content-Length: 0
< Date: Sat, 18 Apr 2020 15:37:56 GMT
< 

```

### 3. Role are respected
> Always inside the `app` container, run this command to test that
> - With `test` or `test2` bearer response is `200`.
> - With `test3` bearer response is `403`.

The command below is composed by two curl. 
  - one curl that generate a jwt token by calling keycloak
  - the second curl use the generated token as a Bearer

#### 3.1 writer can read (user `test`)

```bash
$ export bearer_jwt=$(curl -s \
        -d 'username=test' \
        -d 'password=password' \
        -d 'client_id=client1' \
        -d 'client_secret=7926b321-48ef-4ba9-9c57-ee9c98de7dd6' \
        -d 'grant_type=password' \
        'http://keycloak:8080/auth/realms/organisation/protocol/openid-connect/token' \
        | jq .access_token -r) \
        \
&& curl -v 'localhost:8081/api/private' \
    -H "Authorization: Bearer ${bearer_jwt}"

```

#### 3.2 reader can read (user `test2`)

```bash
$ export bearer_jwt=$(curl -s \
        -d 'username=test2' \
        -d 'password=password' \
        -d 'client_id=client1' \
        -d 'client_secret=7926b321-48ef-4ba9-9c57-ee9c98de7dd6' \
        -d 'grant_type=password' \
        'http://keycloak:8080/auth/realms/organisation/protocol/openid-connect/token' \
        | jq .access_token -r) \
        \
&& curl -v 'localhost:8081/api/private' \
    -H "Authorization: Bearer ${bearer_jwt}"

```

#### 3.3 other roles can't read (user `test3`)

```bash
$ export bearer_jwt=$(curl -s \
        -d 'username=test3' \
        -d 'password=password' \
        -d 'client_id=client1' \
        -d 'client_secret=7926b321-48ef-4ba9-9c57-ee9c98de7dd6' \
        -d 'grant_type=password' \
        'http://keycloak:8080/auth/realms/organisation/protocol/openid-connect/token' \
        | jq .access_token -r) \
        \
&& curl -v 'localhost:8081/api/private' \
    -H "Authorization: Bearer ${bearer_jwt}"

```


> Always inside the `app` container, run this command to test that
> - With `test` bearer response is `200`.
> - With `test2` or `test3` bearer response is `403`.

The curl here is the same as previous, the only difference is `-XPOST` which means that we using the verb POST. 

#### 3.4 writer can write (user `test`)
```bash
$ export bearer_jwt=$(curl -s \
        -d 'username=test' \
        -d 'password=password' \
        -d 'client_id=client1' \
        -d 'client_secret=7926b321-48ef-4ba9-9c57-ee9c98de7dd6' \
        -d 'grant_type=password' \
        'http://keycloak:8080/auth/realms/organisation/protocol/openid-connect/token' \
        | jq .access_token -r) \
        \
&& curl -v 'localhost:8081/api/private' -XPOST \
    -H "Authorization: Bearer ${bearer_jwt}"

```

#### 3.5 other roles can't write (user `test2` and user `test3`)
```bash
$ export bearer_jwt=$(curl -s \
        -d 'username=test2' \
        -d 'password=password' \
        -d 'client_id=client1' \
        -d 'client_secret=7926b321-48ef-4ba9-9c57-ee9c98de7dd6' \
        -d 'grant_type=password' \
        'http://keycloak:8080/auth/realms/organisation/protocol/openid-connect/token' \
        | jq .access_token -r) \
        \
&& curl -v 'localhost:8081/api/private' -XPOST \
    -H "Authorization: Bearer ${bearer_jwt}"

```
```bash
$ export bearer_jwt=$(curl -s \
        -d 'username=test3' \
        -d 'password=password' \
        -d 'client_id=client1' \
        -d 'client_secret=7926b321-48ef-4ba9-9c57-ee9c98de7dd6' \
        -d 'grant_type=password' \
        'http://keycloak:8080/auth/realms/organisation/protocol/openid-connect/token' \
        | jq .access_token -r) \
        \
&& curl -v 'localhost:8081/api/private' -XPOST \
    -H "Authorization: Bearer ${bearer_jwt}"

```

### Code explanation

#### 1. Protect the application with an openid provider

Spring Security provide the starter `spring-boot-starter-oauth2-client` that activate protection of the application using Oauth and Openid Connect proovider.
it support Google / Facebook / Github or custom provider
- by default all endpoints are secured
- token is stored into HttpSession.
- authentification by Authorization header is not supported
- roles based access is not supported

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```
Adding this dependency will not have effect until the `spring.security.oauth2.client.registration` configuration is added

```yaml
spring:
  security:
    oauth2:
      client:
        registration: 
          organisation: 
            client-id: client1
            # client-name: client1
            client-secret: 7926b321-48ef-4ba9-9c57-ee9c98de7dd6
            # client-authentication-method:
            authorization-grant-type: authorization_code
            # http://localhost:8081/login/oauth2/code/organisation
            redirectUri: '{baseUrl}/login/oauth2/code/{registrationId}'
            scope:
              - openid
              - profile
              - email
        provider:
          organisation:
            issuer-uri: http://keycloak:8080/auth/realms/organisation
            user-name-attribute: preferred_username
```

#### 2. Add authentification based on Authorization header

Spring Security provide the `spring-security-oauth2-resource-server` lib that implement a [oauth2 resource server](https://www.oauth.com/oauth2-servers/the-resource-server/). The resource server is the OAuth 2.0 term for your API server. The resource server handles authenticated requests after the application has obtained an access token. This include :

- Verifying Access Tokens included into HTTP Authorization header
- Verifying Scope or Roles
- The following Error codes are implemented
  - invalid_token (HTTP 401) – The access token is expired, revoked, malformed, or invalid for other reasons. The client can obtain a new access token and try again
  - insufficient_scope (HTTP 403) – The access token is valid but don't contains the right roles

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-resource-server</artifactId>
</dependency>

```

After adding this dependency you need to define `spring.security.oauth2.resourceserver.jwt.issuer-uri` or `spring.security.oauth2.resourceserver.jwt.jwk-set-uri` needed to retrieve the JWK Set and verify the signature of the JWT.

Into this example we choose to set the `issuer-uri` 

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://keycloak:8080/auth/realms/organisation
```

#### 3. modify default configuration

The default spring security `WebSecurityConfigurerAdapter` request authentication for any endpoint.

```java
	protected void configure(HttpSecurity http) throws Exception {
...
		http
			.authorizeRequests()
				.anyRequest().authenticated()
...
```
- To override this behavior, we need to provide a custom WebSecurityConfigurerAdapter class and using `@EnableWebSecurity` we activate this class.
- we use the `EnableGlobalMethodSecurity` annotation to enable the `jsr250Enabled` support, this is enable the support of `@RolesAllowed` annotation used into `Contoller` level.
- `SessionCreationPolicy` is set to `STATELESS` to disable HttpSession usage
- The spring security resource server don't map JWT roles to the spring security principal. So we can't use @Secured or @RolesAllowed to manage endpoints based on JWT roles. To fix that we have to implement a custom `jwtAuthenticationConverter`

```java
@EnableWebSecurity
@EnableGlobalMethodSecurity(
		  jsr250Enabled = true)
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	http
// disable usage of HTTP session to store tokens
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
// configure login with oauth2 client 
            .oauth2Login()
            .and()
// activate oauth2 resource server that add authentification with 'Authorization: Bearer' header 
            .oauth2ResourceServer()
            	.jwt()
// add JWT converter to map roles into principal to be able to use into @Secured
            	.jwtAuthenticationConverter(getJwtAuthenticationConverter())
            ;
    }
```
 
#### 4. added authetification using cookie

In this step we provide a custom implementation to `AuthorizedClientRepository`.
We store Access and Refresh token into cookies.
We use an new AuthenticationFilter to attempt authentication using same cookies.

```Java
...
.oauth2Login()
// using custom authorized client repository
// that store tokens into cookies
  .authorizedClientRepository(this.cookieAuthorizedClientRepository())
.and()
// added filter that attempt authentication using cookie stored by CookieAuthorizedClientRepository
  .addFilterAfter(getCookieTokenAuthenticationFilter(http), BearerTokenAuthenticationFilter.class)
...
```

Always inside the `app` container, run this command to test this feature

```bash
export bearer_jwt=$(curl -s \
        -d 'username=test' \
        -d 'password=password' \
        -d 'client_id=client1' \
        -d 'client_secret=7926b321-48ef-4ba9-9c57-ee9c98de7dd6' \
        -d 'grant_type=password' \
        'http://keycloak:8080/auth/realms/organisation/protocol/openid-connect/token' \
        | jq .access_token -r) \
        \
&& curl -v 'localhost:8081/api/private' \
    --cookie "OIDC_ACCESS_TOKEN=${bearer_jwt}"
```
### Reference Documentation

* [Spring Security OAuth2 Client](https://docs.spring.io/spring-boot/docs/2.2.6.RELEASE/reference/htmlsingle/#boot-features-security-oauth2-client)
* [Spring Security Resource Server](https://docs.spring.io/spring-boot/docs/2.2.6.RELEASE/reference/htmlsingle/#boot-features-security-oauth2-server)
* [Resource Server Definition](https://www.oauth.com/oauth2-servers/the-resource-server/)
* [Spring Method Security](https://www.baeldung.com/spring-security-method-security)

### Launch into IDE

To launch this application into our IDE you need to do the following steps

1. Launch keycloak using 
```bash
docker-compose -f src/docker/docker-compose-local.yml up -d
```
2. Launch you application using the local spring profile.
Here is an exemple using maven and spring-boot:run
```bash
./mvnw clean package spring-boot:run -Dspring-boot.run.profiles=local 
```
3. you and test using the following commands

```bash
export bearer_jwt=$(curl -s \
        -d 'username=test' \
        -d 'password=password' \
        -d 'client_id=client1' \
        -d 'client_secret=7926b321-48ef-4ba9-9c57-ee9c98de7dd6' \
        -d 'grant_type=password' \
        'http://localhost:8080/auth/realms/organisation/protocol/openid-connect/token' \
        | jq .access_token -r) \
        \
&& curl -v 'localhost:8081/api/private' \
    -H "Authorization: Bearer ${bearer_jwt}"
```
```bash
export bearer_jwt=$(curl -s \
        -d 'username=test' \
        -d 'password=password' \
        -d 'client_id=client1' \
        -d 'client_secret=7926b321-48ef-4ba9-9c57-ee9c98de7dd6' \
        -d 'grant_type=password' \
        'http://localhost:8080/auth/realms/organisation/protocol/openid-connect/token' \
        | jq .access_token -r) \
        \
&& curl -v 'localhost:8081/api/private' \
    --cookie "OIDC_ACCESS_TOKEN=${bearer_jwt}"

```
### TODO
- howto to manage refresh token
- redirect to the original url after login success

