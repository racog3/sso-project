package com.etfbl.ssoproject.sp.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Created by Rajo on 19.11.2016..
 */

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${sso.sp.path.assertionConsumer}")
    public String ASSERTION_CONSUMER_PATH;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", ASSERTION_CONSUMER_PATH).permitAll()
                .antMatchers("/greeting").hasRole("USER")
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
