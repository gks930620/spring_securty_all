package com.security.jwt.model;

import com.security.jwt.entity.UserEntity;
import java.util.Collection;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


@Getter
public class CustomUserAccount  implements UserDetails {
    private UserEntity userEntity;

    public CustomUserAccount(UserEntity userEntity) {
        this.userEntity = userEntity;
    }

    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }

    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return userEntity.getRoles().stream()
            .map(SimpleGrantedAuthority::new)
            .toList();
    }
}
