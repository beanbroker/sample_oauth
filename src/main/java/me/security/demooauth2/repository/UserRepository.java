package me.security.demooauth2.repository;

import me.security.demooauth2.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {


    User findByUserName(String beanbroker);
}
