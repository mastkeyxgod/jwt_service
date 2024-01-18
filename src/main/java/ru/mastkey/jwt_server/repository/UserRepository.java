package ru.mastkey.jwt_server.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.mastkey.jwt_server.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);

}
