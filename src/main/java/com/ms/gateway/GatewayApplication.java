package com.ms.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication(exclude = {
		// Remove qualquer inicialização automática que venha do pacote do Netflix Eureka
		org.springframework.cloud.netflix.eureka.EurekaClientAutoConfiguration.class
})
public class GatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

}
