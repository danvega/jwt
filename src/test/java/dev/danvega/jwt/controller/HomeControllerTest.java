package dev.danvega.jwt.controller;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;

import dev.danvega.jwt.config.SecurityConfig;
import dev.danvega.jwt.service.TokenService;

@WebMvcTest({ HomeController.class, AuthController.class })
@Import({ SecurityConfig.class, TokenService.class })
class HomeControllerTest {

	@Autowired
	MockMvc mvc;

	@Test
	void rootWhenUnauthenticatedThen401() throws Exception {
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	void rootWhenAuthenticatedThenSaysHelloUser() throws Exception {
		MvcResult result = this.mvc.perform(post("/token").with(httpBasic("dvega", "password"))).andExpect(status().isOk()).andReturn();

		String token = result.getResponse().getContentAsString();

		this.mvc.perform(get("/").header("Authorization", "Bearer " + token)).andExpect(content().string("Hello, dvega"));
	}

	@Test
	@WithMockJwtAuth
	public void rootWithMockUserStatusIsOK() throws Exception {
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	@WithMockJwtAuth("SCOPE_read")
	public void securedWithReadStatusIsOK() throws Exception {
		this.mvc.perform(get("/secure")).andExpect(status().isOk());
	}

	@Test
	@WithMockJwtAuth
	public void securedWithoutReadStatusIsForbidden() throws Exception {
		this.mvc.perform(get("/secure")).andExpect(status().isForbidden());
	}

}