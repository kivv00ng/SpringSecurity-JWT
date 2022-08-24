package com.cos.security1.model;

import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy =  GenerationType.IDENTITY)
    private int id;
    private String username;
    private String password;
    private String email;
    private String roles; //ROLE_USER, ROLE_ADMIN
    @CreationTimestamp
    private Timestamp createDate;

    private String provider;
    private String providerId;

    public int getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getEmail() {
        return email;
    }

    public List<String> getRoleList(){
        if(this.roles.length() >0){
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>();
    }


    protected User(){}

    public static User CreateUser(String username, String password, String email, String roles, String provider, String providerId){
        User user = new User();

        user.username = username;
        user.password = password;
        user.email = email;
        user.roles = roles;
        user.provider = provider;
        user.providerId = providerId;

        return user;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", email='" + email + '\'' +
                ", roles='" + roles + '\'' +
                ", createDate=" + createDate +
                ", provider='" + provider + '\'' +
                ", providerId='" + providerId + '\'' +
                '}';
    }
}
