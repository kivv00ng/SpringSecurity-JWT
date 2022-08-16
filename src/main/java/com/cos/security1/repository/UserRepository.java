package com.cos.security1.repository;

import com.cos.security1.model.User;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;

@Repository
@RequiredArgsConstructor
public class UserRepository{

    private final EntityManager em;

    @Transactional
    public void save(User user){
        em.persist(user);
    }

    public User findOne(Long id){
        return em.find(User.class, id);
    }


    @Transactional(readOnly = true)
    public User findByUsername(String username) {
        User userEntity = em.createQuery("select m from User m where m.username =: username", User.class)
                .setParameter("username", username)
                .getSingleResult();
        return userEntity;
    }
}
