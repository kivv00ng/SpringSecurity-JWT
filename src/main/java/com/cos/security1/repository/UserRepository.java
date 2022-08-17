package com.cos.security1.repository;

import com.cos.security1.model.User;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class UserRepository{

    private final EntityManager em;

    @Transactional
    public void save(User user){
        em.persist(user);
    }

    @Transactional(readOnly = true)
    public User findByUsername(String username) {
        List<User> users = em.createQuery("select m from User m where m.username =: username", User.class)
                .setParameter("username", username)
                .getResultList();
        if(users.isEmpty()){
            return null;
        }
        return users.get(0);
    }
}
