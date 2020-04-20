package com.example.demoopenidconnect.controller;

import javax.annotation.security.RolesAllowed;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController()
@RequestMapping("/")
public class RestResource {

	
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
}
