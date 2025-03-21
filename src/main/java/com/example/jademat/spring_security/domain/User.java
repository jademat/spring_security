package com.example.jademat.spring_security.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "users2")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String userid;
    @Column(nullable = false)
    private String passwd;
    @Column(nullable = false,unique = true)
    private String name;
    @Column(nullable = false)
    private String email;

    // insert, update 시 해당컬럼 제외
    @CreationTimestamp
    // @Column(insertable = false, updatable = false)
    private LocalDateTime regdate;

}
