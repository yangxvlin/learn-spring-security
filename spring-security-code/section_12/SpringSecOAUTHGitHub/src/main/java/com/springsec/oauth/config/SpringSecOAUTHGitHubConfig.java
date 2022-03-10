package com.springsec.oauth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SpringSecOAUTHGitHubConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().anyRequest().authenticated().and().oauth2Login();
	}

	/*
	 * private ClientRegistration clientRegistration() { return
	 * CommonOAuth2Provider.GITHUB.getBuilder("github").clientId(
	 * "e482d40474aaaec77980")
	 * .clientSecret("dcd7d4f3b2fabeaf8a8646b0d1d653a4378170e9").build(); }
	 */

	
	/*
	 * private ClientRegistration clientRegistration() { ClientRegistration cr =
	 * ClientRegistration.withRegistrationId("github").clientId(
	 * "3c9be97074f067e78e75")
	 * .clientSecret("ab313f7ade3d79e06c192ca80cf152c43cb5d916").scope(new String[]
	 * { "read:user" })
	 * .authorizationUri("https://github.com/login/oauth/authorize")
	 * .tokenUri("https://github.com/login/oauth/access_token").userInfoUri(
	 * "https://api.github.com/user")
	 * .userNameAttributeName("id").clientName("GitHub")
	 * .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	 * .redirectUriTemplate("{baseUrl}/{action}/oauth2/code/{registrationId}").build
	 * (); return cr; }
	 */
	 

	/*
	 * @Bean public ClientRegistrationRepository clientRepository() {
	 * ClientRegistration clientReg = clientRegistration(); return new
	 * InMemoryClientRegistrationRepository(clientReg); }
	 */

}
