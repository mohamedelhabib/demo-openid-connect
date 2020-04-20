package com.example.demoopenidconnect.security;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
	
	private static final String ROLES_CLAIM_NAME = "resource_access";
	private static final String ROLE_PREFIX = "ROLE_";
	private static final String RESOURCE_ID = "client1";

	/**
	 * parsing and mapping roles into GrantedAuthority
	 * <pre>
	 * "resource_access": {
	 *     ...
	 *     "client1": {
	 *       "roles": [
	 *         "reader"
	 *         "writer"
	 *       ]
	 *     }
	 *     ...
	 *   }
	 * </pre>
	 **/
	private Stream<SimpleGrantedAuthority> extractResourceRoles(final Jwt jwt) {
		Map<String, Map<String, Collection<String>>> resourceAccess = jwt.getClaim(ROLES_CLAIM_NAME);
		return resourceAccess.entrySet().stream()
			.filter(resource -> RESOURCE_ID.equals(resource.getKey()))
			.flatMap(resource -> resource.getValue().entrySet().stream())
			.filter(roles -> "roles".equals(roles.getKey()))
			.flatMap(roles -> roles.getValue().stream())
			.map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
			;
	}

	private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

	@Override
	public AbstractAuthenticationToken convert(final Jwt source) {
		Collection<GrantedAuthority> authorities = Stream
				.concat(defaultGrantedAuthoritiesConverter.convert(source).stream(),
						extractResourceRoles(source))
				.collect(Collectors.toSet());
		return new JwtAuthenticationToken(source, authorities);
	}
}