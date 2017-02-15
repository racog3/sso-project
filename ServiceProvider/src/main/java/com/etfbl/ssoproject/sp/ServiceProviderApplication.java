package com.etfbl.ssoproject.sp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
//@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class})
public class ServiceProviderApplication {

	public static void main(String[] args) {
		SpringApplication.run(ServiceProviderApplication.class, args);
	}
}
