package dev.danvega.jwt.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;

import dev.danvega.jwt.config.SecurityConfig;

@WebMvcTest({ HomeController.class })
@AutoConfigureAddonsWebSecurity
@Import({ SecurityConfig.class })
class HomeControllerTest {

	@Autowired
	MockMvc mvc;

	@Test
	void rootWhenUnauthenticatedThen401() throws Exception {
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockJwtAuth
	public void rootWithMockUserStatusIsOK() throws Exception {
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	@WithMockJwtAuth("SCOPE_read")
	public void secureWithJwtAndReadStatusIsOK() throws Exception {
		this.mvc.perform(get("/secure")).andExpect(status().isOk());
	}

	@Test
	@WithMockJwtAuth
	public void secureWithJwtWithoutReadStatusIsForbidden() throws Exception {
		this.mvc.perform(get("/secure")).andExpect(status().isForbidden());
	}

}