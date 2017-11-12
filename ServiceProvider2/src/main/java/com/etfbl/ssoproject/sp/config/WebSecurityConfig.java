package com.etfbl.ssoproject.sp.config;

import com.etfbl.ssoproject.idp.client.SSOUtility;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${sso.sp.path.assertionConsumer}")
    public String ASSERTION_CONSUMER_PATH;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", ASSERTION_CONSUMER_PATH, SSOUtility.LOGOUTREQUEST_PROCESSING_PATH).permitAll()
                .antMatchers("/protectedResource", "/protectedResource2").hasRole("USER")
                .anyRequest().authenticated()
                .and()
                .csrf().ignoringAntMatchers(ASSERTION_CONSUMER_PATH)
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll();
    }
}
