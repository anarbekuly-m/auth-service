package pro.hiking.auth.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Data
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true) // <--- уникальный email
    private String email;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

}