package restapi.jwt.repository;

import restapi.jwt.model.ERole;
import restapi.jwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IRoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
    Role findByName(String role);
}
