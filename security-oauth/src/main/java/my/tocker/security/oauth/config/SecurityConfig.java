package my.tocker.security.oauth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        log.info("inmemory user define...");
        auth
            .inMemoryAuthentication()

            .withUser("tocker").password("1234")
            .roles("USER")

            .and()

            .withUser("admin").password("1234")
            .roles("USER", "ADMIN")
        ;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .formLogin()

            .and()

            .httpBasic().disable()
            .anonymous().disable()
            .authorizeRequests().anyRequest().authenticated()
        ;
    }
}
