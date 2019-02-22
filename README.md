# SpringSecurity가 궁금한 히치하이커를 위한 안내서
<초보자도 이해하는 SpringSecurity guide>

스프링시큐리티를 처음 공부하시는 여러분을 위한 초보자 가이드 입니다.

* [step1 - 유저 모델링](#step1) 
* [step2 - 회원가입 ](#step2)
* [step3 - 로그인 (bad.ver) ](#step3)

<h2 id="step1">step1 - 유저 모델링 </h2>

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

<br></br>

<div id="step2"><h2> step2 - 회원가입</h2></div>

우선 데이터베이스에 회원 정보를 넣어주기 위해 `repository`와 `service`를 생성하겠습니다.

**MemberRepository**
```java
@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByEmail(String email);

}

```
**MemberService**
```java
@Service
@Slf4j
public class MemberService implements UserDetailsService {

    @Autowired
    MemberRepository memberRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Transactional
    public Member singUp(Member member){
        log.info(member.getEmail());
        member.setPassword(
                passwordEncoder.encode(member.getPassword())
        );
        member.setRole(MemberRole.USER);

        return memberRepository.save(member);
    }

    //todo 로그인 시 사용
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return null;
    }

}
```

회원정보를 DB에 넣을 때, 비밀번호를 암호화 하기위해 `SecurityConfig`파일을 작성 후
`PasswordEncoder`를 빈으로 설정하겠습니다.

`SecurityConfig`에서는 비밀번호 암호화 이외에도 여러 `security`관련 설정을 지원힙니다.


```java
@Configuration
@EnableWebSecurity // @Configuration 클래스에 WebSecurityConfigurerAdapter를 확장하거나 WebSecurityConfigurer를 정의하여 보안을 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true) //추 후에 @PreAuthorize 를 이용하기 위해 사용
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
```
* `@EnableWebSecurity` 에노테이션은 `@Configuration` 
클래스에 `WebSecurityConfigurerAdapter`를 확장하거나 
`WebSecurityConfigurer`를 정의하여 보안을 활성화 하는 역할을 합니다.

* `@EnableGlobalMethodSecurity(prePostEnabled = true)`은 추 후에 
`@PreAuthorize` 를 이용하기 위함입니다.

🔓🔓 **@EnableWebSecurity** 

```java
@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = { java.lang.annotation.ElementType.TYPE })
@Documented 
@Import({ WebSecurityConfiguration.class,
		SpringWebMvcImportSelector.class,
		OAuth2ImportSelector.class })
@EnableGlobalAuthentication
@Configuration
public @interface EnableWebSecurity {
	boolean debug() default false;
}
```
`EnableWebSecurity`의 구현을 보면 `WebSecurityConfiguration`가 `import`되어있을음 알 수 있습니다.
<br></br>

저는 추가적으로 h2 DB에 접근하기 위한 설정을 `SecurityConfig`에 추가적으로 넣어줬습니다.

`HttpSecurity`는 http 요청에 대해 웹기반 보안기능을 구성할 수 있습니다.
```java
@Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .headers().frameOptions().disable();
        http
                .csrf().disable();
        http
                .authorizeRequests()
                .antMatchers("/h2-console/**").permitAll();
    }
```
<br></br>
마지막으로 `controller`를 작성하겠습니다. 

**AuthController**
```java
@RestController
public class AuthController {

    @Autowired
    MemberService memberService;

    @PostMapping("/signUp")
    public String signUp(@RequestBody Member member){
        memberService.singUp(member);
        return "ok";
    }
}
```

<br></br>

<h2 id="step3">step3 - 로그인 (bad.ver) </h2>

이 부분은 최소한의 부분으로 구현한 로그인절차입니다. 로그인이 성공하면 토큰을
주는 방식으로 진행하겠습니다.

bad version에서 로그인 요청이 들어왔을 때 절차는

**요청 -> filter -> 응답**

이러한 순서로 동작합니다.

먼저 `filter`를 구현하기 전에 `jwt`를 생성할 클래스와 `loginDto` 그리고 
`UserDetails`를 구현하겠습니다.

>**이미 `Member`라는 유저 객체가 있는데 `UserDetails`는 뭔가요?**

>`UserDetails`는 인증 객체로서 사용자 정보를 저장합니다.
><--는 `javadoc`에서 발최한 부분으로 더욱 직관적으로 설명하자면 로그인할 때
>필요한 `UserDetailsService` 의 `loadUserByUsername`함수를 보시면 
>반환값이 `UserDetails`인 것을 볼 수 있습니다. 이렇듯 `springsecurity`
>에서는 하나의 규격화된 `UserDetails`인터페이스를 상속 받은 클래스를 사용자로 인식하고
>인증합니다. 







 


