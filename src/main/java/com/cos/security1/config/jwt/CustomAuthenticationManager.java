package com.cos.security1.config.jwt;

import com.cos.security1.config.auth.CustomBCryptPasswordEncoder;
import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.auth.PrincipalDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationManager implements AuthenticationManager {

    private final CustomBCryptPasswordEncoder bCryptPasswordEncoder;
    private final PrincipalDetailsService principalDetailsService;

    //출처:https://stackoverflow.com/questions/71281032/spring-security-exposing-authenticationmanager-without-websecurityconfigureradap
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PrincipalDetails principalDetails = (PrincipalDetails) principalDetailsService.loadUserByUsername(authentication.getName());

        if(!bCryptPasswordEncoder.matches(authentication.getCredentials().toString(), principalDetails.getPassword())){
           throw new BadCredentialsException("Wrong password!");
        }

        /*
        public UsernamePasswordAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal; //아이디
		this.credentials = credentials; //비밀번호
		super.setAuthenticated(true); // must use super, as we override
	}
         */
        return new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
        //return new UsernamePasswordAuthenticationToken(principalDetails.getUsername(), principalDetails.getPassword(), principalDetails.getAuthorities());
    }

      /*
    @Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			if (this.delegate != null) {
				return this.delegate.authenticate(authentication);
			}
			synchronized (this.delegateMonitor) {
				if (this.delegate == null) {
					this.delegate = this.delegateBuilder.getObject();
					this.delegateBuilder = null;
				}
			}
			return this.delegate.authenticate(authentication);
		}
     */
}
