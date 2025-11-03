package com.luiggi.springcloud.msvc.oauth.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;
import java.util.stream.Collectors;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.core.userdetails.User;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
// import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
public class SecurityConfig {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
                // configura la cadena filtro de autenticacion con username y password
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				OAuth2AuthorizationServerConfigurer.authorizationServer();

		http
			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.with(authorizationServerConfigurer, (authorizationServer) ->
				authorizationServer
					.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
			)
			.authorizeHttpRequests((authorize) ->
				authorize
					.anyRequest().authenticated()
			)
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			);

		return http.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
                // configuracion de rutas
                // todas las rutas del servidor de autorizacion requieren autenticacion
                // excepto el formulario login que es de acceso publico
		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
			.csrf(csrf -> csrf.disable()) // deshabilita el token de formulario
			.formLogin(Customizer.withDefaults());

		return http.build();
	}

	// @Bean
	// UserDetailsService userDetailsService() {
    //     // configuracion de los usuarios 
	// 	UserDetails userDetails = User.builder()
	// 			.username("luiggi")
	// 			.password("{noop}12345") //inidica que la contraseña se escribe tal cual, sin encriptacion
	// 			.roles("USER")
	// 			.build();
            
    //     UserDetails admin = User.builder()
	// 			.username("admin")
	// 			.password("{noop}12345")
	// 			.roles("USER", "ADMIN")
	// 			.build();

    //     // tenemos 2 usuarios configurados, usuarios en memoria, valido para desarrollo, para probar, para una app pequeña

	// 	return new InMemoryUserDetailsManager(userDetails, admin);
    //     /**
    //      *  si ya tenemos los usuarios en el msvc users, para que tener aqui usuarios?
    //      * - primero vamos a partir con usuarios del msvc oauth(este), es decir con usuarios en memoria,
    //      * como una bd virtual
    //      * - cuando lo tengamos bien configurado usando la memoria
    //      * - migramos con los usuaios del msvc users y nos comunicaremos con una api
    //      */
	// }

	@Bean 
	RegisteredClientRepository registeredClientRepository() {
        // configuracion de los clientes que se registraran en la app
        /**
         * apps cliente: angular, react
		 * la siguiente configuracion es para proteger gateway, si quieres proteger otros mscv en particular
		 * se crearian otros
         */
		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("gateway-app")
				.clientSecret(passwordEncoder.encode("12345"))
				// .clientSecret("{noop}12345")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://127.0.0.1:8090/login/oauth2/code/client-app") // 8090: porque se protegera gateway, al proteger gateway protego todos los msvc, esta ruta(login) ya viene por defecto, no se implementa
				.redirectUri("http://127.0.0.1:8090/authorized") // ruta que vamos a implementar
				.postLogoutRedirectUri("http://127.0.0.1:8090/logout")  // ruta de logout, se define algun endpoint en gateway para hacer logtout
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.tokenSettings(TokenSettings
					.builder()
					.accessTokenTimeToLive(Duration.ofHours(2))
					.refreshTokenTimeToLive(Duration.ofDays(1))
					.build()
				)
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
				.build();

		return new InMemoryRegisteredClientRepository(oidcClient);
	}

	// se genera una llave publica y privada(metodo jwkSource) para generar una llave secreta
	// que nos permite generar el token
	// - cuando se genera el token nos permite firmar este token con esa llave secreta
	// - la llave secreta se mantiene privada, ni siquiera desde el backend se puede ver, pero el back si la guarda(se guarda en este servidor de autorizacion)
	// - si se llega a modificar el token la llave se rompe
	@Bean
	JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			// algoritmo par generar la llave: RSA
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	// decodifica el token
	@Bean 
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean 
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	// Personlizamos el token para agregar los roles
	// - Al momento de crear el token agregará estos roles
	// - Estos roles vienen del usuario
	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			// Modificamos el token del tipo ACCESS_TOKEN
			if(context.getTokenType().getValue() == OAuth2TokenType.ACCESS_TOKEN.getValue()){
				Authentication principal = context.getPrincipal(); // Obtenemos el contexto de autenticación, en este contexto estan los roles
				context.getClaims()
					.claim("data", "data adicional en el token...")
					.claim(
						"roles", 
						// - Inicialmente los roles vienen como una lista roles/permisos del usuario autenticado
						// - Cada elemento de esta lista es un objeto del tipo GrantedAuthority
						// - Pero lo necesitamos en una lista de string para guardarlo en el token
						principal.getAuthorities().stream()
							.map(GrantedAuthority::getAuthority)
							.collect(Collectors.toList())
					); // Con claim agregamos data adicional al token
			}
		};
	}

}
