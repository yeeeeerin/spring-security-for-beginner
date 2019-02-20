# SpringSecurity가 궁금한 히치하이커를 위한 안내서
<초보자도 이해하는 SpringSecurity guide>

스프링시큐리티를 처음 공부하시는 여러분을 위한 초보자 가이드 입니다.


##step1 - 유저 모델링
**Member class**
```java
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Long id;

    @Column(name = "MEMBER_EMAIL")
    private String email;

    @Column(name = "MEMBER_USERNAME")
    private String username;

    @Column(name = "MEMBER_PASSWORD")
    private String password;

    @Column(name = "MEMBER_ROLE")
    @Enumerated(value = EnumType.STRING)
    private MemberRole role;

}
```
아주 최소한의 정보인 `email, username, password, role`으로만 `Member`를 구성하였습니다.

`class`이름을 `User`로 하지 않는 것을 권장합니다.
`org.springframework.security.core.userdetails.User`와 같이 
`spring security`에 이미 `user`가 있음으로 `class`이름을 `User`로 하지 않는 것을 권장합니다.



**MemberRole**
```java
@Getter
public enum  MemberRole {

    ADMIN("ROLE_ADMIN"), USER("ROLE_USER");

    private String roleName;

    MemberRole(String roleName) {
        this.roleName = roleName;
    }

}

```
기본적으로 `admin`과 `user`의 권한만 만들어 진행하겠습니다.

`Spring Security`규정상 `role`은 기본적으로 '`ROLE_`'로 시작해야 합니다. 
그래야 권한을 인식할 수 있습니다. '`ROLE_`'이라는 접두어를 다른 접두어로 변경하고 
싶으면 추가적으로 설정이 필요함으로 `step1`에서는 넘어가도록 하겠습니다.
 


