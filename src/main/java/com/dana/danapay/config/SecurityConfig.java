package com.dana.danapay.config;

import com.dana.danapay.security.*;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.cglib.core.internal.CustomizerRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@EnableWebSecurity  // 시큐리티 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint; // 403 code
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;           // 401 code

    // 시큐리티 설정무시 정적 리소스 빈 등록
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring().requestMatchers("/css/**", "/js/**", "/static/**", "/templates/**");
    }

    // http 요청 권한설정
    @Bean
    public SecurityFilterChain filterChain(@NotNull HttpSecurity http) throws Exception {

        http.httpBasic(HttpBasicConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .cors(custom -> custom.configurationSource(new CorsConfig().corsFilter()))
                .sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(
                        author -> author
                                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                .requestMatchers("/api/**").permitAll()
                                .anyRequest().permitAll()
//                                .requestMatchers("/api/orders").hasAnyRole("'USER','STORE','ADMIN")
                )
                .exceptionHandling(AuthenticationManager -> AuthenticationManager
                        .authenticationEntryPoint(new JwtAuthenticationEntryPoint())
                        .accessDeniedHandler(new JwtAccessDeniedHandler()))
                .addFilterBefore(new JwtFilter(this.tokenProvider),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


}
