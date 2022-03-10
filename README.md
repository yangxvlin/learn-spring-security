# learn-spring-security

## resource
- [udemy course](https://www.udemy.com/course/spring-security-zero-to-master/)
    - [GitHub material](https://github.com/eazybytes/spring-security)
    - [slides](./docs/Spring+Security+Zero+to+Master+along+with+JWT,OAUTH2.pdf)

## section 1: spring security basics
In pom.xml
```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId> <!--> enables soring security, i.e.: prompt /login if accessing unauthorized page <-->
    </dependency>
    ...
</dependencies>
```

### default account
[link](./spring-security-code/section1/springsecuritybasic/src/main/resources/application.properties)

### multiple requests without crediential by spring-security
- without auth:  
    - <img src="./imgs/1.png" width="40%"/>  
- with auth:  
    - <img src="./imgs/2.png" width="40%"/>
- multiple times enabled by value stored in cookie
    - <img src="./imgs/3.png" width="40%"/>


### spring securith flow
- <img src="./imgs/4.png" width="90%"/>
1. AuthenticationFilter: 
    - A filter that intercepts and performs authentication of a particular request by delegating it to the authentication manager If authentication is successful, the authentication details is set into SecurityContext
2. Authentication: 
    - Using the supplied values from the user like username and password, the authentication object will be formed which will be given as an input to the AuthenticationManager interface
3. AuthenticationManager: 
    - Once received request from filter it delegates the validating of the user details to the authentication provider
4. AuthenticationProvider **<u>(business logic)</u>**: 
    - It has all the logic of validating user details using UserDetailsService and PasswordEncoder
5. UserDetailsService: 
    - UserDetailsService retrieves UserDetails and implements the User interface using the supplied username
6. PasswordEncoder: 
    - Service interface for encoding passwords
7. SecurityContext: 
    - Interface defining the minimum security information associated with the current thread of execution It holds the authentication data post successful authentication **<u>(stores the details of the currently authenticated user inside Spring Security framework)</u>**

## section 2: changing the default secuirty configurations
- Services with out any security
    - /contact
        - This service should accept the details from the Contact Us page in the UI and save to the DB.
    - /notices
        - This service should send the notice details from the DB to the ‘NOTICES’ page in the UI
- Services with security
    - /myAccount
        - This service should send the account details of the logged in user from the DB to the UI
    - /myBalance
        - This service should send the balance and transaction details of the logged in user from the DB to the UI
    - /myLoans
        - This service should send the loan details of the logged in user from the DB to the UI
    - /myCards
        - This service should send the card details of the logged in user from the DB to the UI
- default behavior:
    - authenticate all methods for all users
- configure above security permission: [ProjectSecurityConfig.java](./spring-security-code\section2\springsecsection2\src\main\java\com\eazybytes\config\ProjectSecurityConfig.java)
    ```java
    /**
     * Custom configurations as per our requirement
     */
    http
        .authorizeRequests()
            .antMatchers("/myAccount").authenticated()
            .antMatchers("/myBalance").authenticated()
            .antMatchers("/myLoans").authenticated()
            .antMatchers("/myCards").authenticated()
            .antMatchers("/notices").permitAll()
            .antMatchers("/contact").permitAll()
            .and()
        .formLogin().and()
        .httpBasic();
    ```



