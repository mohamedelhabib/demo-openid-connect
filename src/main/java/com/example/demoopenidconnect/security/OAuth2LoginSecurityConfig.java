package com.example.demoopenidconnect.security;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled = true)
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	private static final String OIDC_REFRESH_TOKEN = "OIDC_REFRESH_TOKEN";
	private static final String OIDC_ACCESS_TOKEN = "OIDC_ACCESS_TOKEN";

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				// disable usage of HTTP session to store tokens
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				// configure login with oauth2 client
				.oauth2Login()
				// using custom authorized client repository
				// that store tokens into cookies
					.authorizedClientRepository(this.cookieAuthorizedClientRepository())
				.and()
					.addFilterAfter(getCookieTokenAuthenticationFilter(http), BearerTokenAuthenticationFilter.class)
				// activate oauth2 resource server that add authentification with
				// 'Authorization: Bearer' header
				.oauth2ResourceServer()
					.jwt()
				// add JWT converter to map roles into principal to be able to use into @Secured
					.jwtAuthenticationConverter(getJwtAuthenticationConverter())

		;
	}

	private Converter<Jwt, AbstractAuthenticationToken> getJwtAuthenticationConverter() {
		return new CustomJwtAuthenticationConverter();
	}

	private CookieTokenAuthenticationFilter getCookieTokenAuthenticationFilter(HttpSecurity http) throws Exception {
		return new CookieTokenAuthenticationFilter(http);
	}

	private OAuth2AuthorizedClientRepository cookieAuthorizedClientRepository() {
		return new OAuth2AuthorizedClientRepository() {

			@Override
			public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal,
					HttpServletRequest request, HttpServletResponse response) {
				storeIntoCookies(response, authorizedClient);
			}

			@Override
			public void removeAuthorizedClient(String clientRegistrationId, Authentication principal,
					HttpServletRequest request, HttpServletResponse response) {
			}

			@Override
			public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId,
					Authentication principal, HttpServletRequest request) {
				return null;
			}
		};
	}

	class CookieTokenAuthenticationFilter extends OncePerRequestFilter {

		private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

		private HttpSecurity http;

		public CookieTokenAuthenticationFilter(HttpSecurity http) {
			this.http = http;
		}

		protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
			return request.getCookies() == null;
		}

		/**
		 * Extract <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target=
		 * "_blank">Access Token</a> from the OIDC_ACCESS_TOKEN cookie and attempt an authentication.
		 *
		 * @param request
		 * @param response
		 * @param filterChain
		 * @throws ServletException
		 * @throws IOException
		 */
		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
				FilterChain filterChain) throws ServletException, IOException {

			final boolean debug = this.logger.isDebugEnabled();

			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			
			if (authentication != null) {
				filterChain.doFilter(request, response);
				return;
			}

			String token = loadAccessTokenFromCookie(request);
			
			if (token == null) {
				filterChain.doFilter(request, response);
				return;
			}
	
			BearerTokenAuthenticationToken authenticationRequest = new BearerTokenAuthenticationToken(token);
	
			authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
	
			try {
				AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
				Authentication authenticationResult = authenticationManager.authenticate(authenticationRequest);
				SecurityContext context = SecurityContextHolder.createEmptyContext();
				context.setAuthentication(authenticationResult);
				SecurityContextHolder.setContext(context);
			} catch (AuthenticationException failed) {
				SecurityContextHolder.clearContext();
				if (debug) {
					this.logger.debug("Authentication request with cookie failed", failed);
				}
			}
			filterChain.doFilter(request, response);
		}
	}

	private void storeIntoCookies(HttpServletResponse response, OAuth2AuthorizedClient authorizedClient) {
		response.addCookie(createCookie(OIDC_ACCESS_TOKEN, authorizedClient.getAccessToken().getTokenValue()));
		response.addCookie(
				createCookie(OIDC_REFRESH_TOKEN, authorizedClient.getRefreshToken().getTokenValue()));
	}

	private Cookie createCookie(String name, String value) {
		Cookie cookie = new Cookie(name, value);
		cookie.setHttpOnly(true);
		cookie.setPath("/");
		return cookie;
	}
	
	private String loadAccessTokenFromCookie(HttpServletRequest request) {
		String token = null;
		Cookie[] cookies = request.getCookies();
		if( cookies != null) {
			Optional<Cookie> cookie = Arrays.asList(cookies).stream()
			.filter(c -> OIDC_ACCESS_TOKEN.equals(c.getName())).findAny();
			if (cookie.isPresent()) {
				token = cookie.get().getValue();
			}	
		}
		return token;
	}
}