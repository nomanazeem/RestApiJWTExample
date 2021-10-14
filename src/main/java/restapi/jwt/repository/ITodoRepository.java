package restapi.jwt.repository;

import restapi.jwt.model.Todo;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ITodoRepository extends JpaRepository<Todo, Long> {
    List<Todo> findByName(String name);

    @Query(nativeQuery = true, value="select * from todo t " +
            "where 1=1 " +
            "and (t.name like %:criteria% " +
            "   or t.status like %:criteria%)")
    Page<Todo> searchTodo(String criteria, Pageable pageable);
}
