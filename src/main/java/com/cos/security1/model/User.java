package com.cos.security1.model;

import lombok.Builder;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.sql.Timestamp;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy =  GenerationType.IDENTITY)
    private int id;
    private String username;
    private String password;
    private String email;
    private String role; //ROLE_USER, ROLE_ADMIN
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

    public String getRole() {
        return role;
    }

    public Timestamp getCreateDate() {
        return createDate;
    }

    protected User(){}


    public static User CreateUser(String username, String password, String email, String role, String provider, String providerId){
        User user = new User();

        user.username = username;
        user.password = password;
        user.email = email;
        user.role = role;
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
                ", role='" + role + '\'' +
                ", createDate=" + createDate +
                ", provider='" + provider + '\'' +
                ", providerId='" + providerId + '\'' +
                '}';
    }
}
