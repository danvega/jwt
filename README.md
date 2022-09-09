# Spring Security JWT

If you perform a quick search on how to secure your REST APIs in Spring Boot using JSON Web Tokens you will find a lot of the same results. These results contain a method that involves writing a custom filter chain and pulling in a 3rd party library for encoding and decoding JWTs.

I knew there had to be an easier way so I did what anyone with direct access to the Spring Security team would do, I asked them for help. They informed me that indeed Spring Security has built-in support for JWTs using oAuth2 Resource Server.

In this tutorial you are going to learn how to secure your APIs using JSON Web Tokens (JWT) with Spring Security. I’m not saying this approach is easy by any stretch but for me it made a lot more sense than the alternatives.