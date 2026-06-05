package com.ms.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Value("${api.security.token.secret}")
    private String secret;

    public AuthenticationFilter() {
        super(Config.class);
    }

    public static class Config {
        // Classe de configuração exigida pelo Spring (pode deixar vazia)
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            // 1. Verifica se a requisição possui o token
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Faltou o token", HttpStatus.UNAUTHORIZED);
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return onError(exchange, "Token mal formatado", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);

            try {
                // 2. Descriptografa e lê o payload do Token
                SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                // 3. Extrai a role (perfil) salva dentro do Token
                String role = claims.get("role", String.class);
                if (role == null) {
                    role = "";
                }

                // ========================================================================
                // 🛡️ REGRAS DE AUTORIZAÇÃO (RBAC)
                // ========================================================================

                // Regra: Apenas ADMIN pode listar a base de professores
                if (path.contains("/api/professores") && request.getMethod().name().equals("GET")) {
                    if (!role.toUpperCase().contains("ADMIN")) {
                        return onError(exchange, "Acesso Negado: Apenas Administradores", HttpStatus.FORBIDDEN);
                    }
                }

                // Você pode adicionar mais regras de RBAC aqui no futuro!
                // Exemplo: if (path.contains("/api/escolas") && ... )

                // ========================================================================

                // 4. Injeta os dados nos headers para o microsserviço de destino saber quem é
                ServerHttpRequest mutatedRequest = request.mutate()
                        .header("X-User-Email", claims.getSubject())
                        .header("X-User-Role", role)
                        .build();

                return chain.filter(exchange.mutate().request(mutatedRequest).build());

            } catch (Exception e) {
                return onError(exchange, "Token inválido ou expirado", HttpStatus.FORBIDDEN);
            }
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);

        // Adiciona a mensagem de erro no Header da resposta para você conseguir ler no Postman!
        response.getHeaders().add("X-Auth-Error", err);

        return response.setComplete();
    }
}