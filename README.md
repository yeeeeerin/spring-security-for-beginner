# SpringSecurity가 궁금한 히치하이커를 위한 안내서
<초보자도(가) 이해하는 SpringSecurity guide>

스프링시큐리티를 처음 공부하시는 여러분을 위한 초보자 가이드 입니다.

* [step1 - 유저 모델링](#step1) 
* [step2 - 회원가입 ](#step2)
* [step3 - 로그인](#step3)

<br></br>
❗[必부록]

* [step3-참고 JWT란](#att)


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
@EnableWebSecurity 
@EnableGlobalMethodSecurity(prePostEnabled = true)
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

🔐 **@EnableWebSecurity** 

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

<h2 id="step3">step3 - 로그인</h2>

로그인이 성공하면 `JWT token`을 부여하는 방식으로 진행하겠습니다.

아래는 `login` 요청이 들어왔을 때의 절차 입니다.

1. 요청이 들어오면 `AbstractAuthenticationProcessingFilter`에 들어가게 됩니다.
2. 그 다음 `filter`의 `attemptAuthenticationg`메소드를 통해 유저의
정보가 담긴 `Authentication`객체(인증 전)를 `AuthenticationManager`에 전달합니다.
    1. `Authentication`객체는 `UsernamePasswordAuthenticationToken`을 통해
    만듭니다.
3. 내부적으로 `Spring Security`의 `ProviderManager`를 통해 적잘한 
`AuthenticationProvider`를 찾습니다.
4. `AuthenticationProvider`의 `authenticate`메소드로 인증을 진행합니다.
5. 인증에 성공했다면 성공한 `Authentication`객체(인증 후)를 `filter`에 다시 반환해 
`authenticationSuccessHandler`를 수행합니다.
6. `authenticationSuccessHandler`를 통해 `jwt token`을 발급하고 `response`를 채워줍니다.

</br>

먼저 filter와 provider를 구현하기 전에 몇가지 작업을 해야합니다.

**LoginMemberDto**
```java
@Data
public class LoginMemberDto {
    String email;
    String password;
}
```
단순한 email과 password를 받는 dto입니다.

**SecurityMember**
```java
public class SecurityMember extends User {


    public SecurityMember(String email, String password, Collection<? extends GrantedAuthority> authorities) {
        super(email, password, authorities);
    }

    public static SecurityMember getMemberDetails(Member member) {
        return new SecurityMember(member.getEmail(),member.getPassword(),parseAuthorities(member.getRole()));
    }

    private static List<SimpleGrantedAuthority> parseAuthorities(MemberRole role) {
        return Arrays.asList(role).stream()
                .map(r -> new SimpleGrantedAuthority(r.getRoleName()))
                .collect(Collectors.toList());
    }
}
```
회원정보를 가지고 있는 인증객체인 `userdetails`를 구현해야합니다.

>**이미 `Member`라는 유저 객체가 있는데 `UserDetails`는 뭔가요?**

>`UserDetails`는 인증 객체로서 사용자 정보를 저장합니다. 
<--는 `javadoc`에서 발최한 부분으로 더욱 직관적으로 설명하자면 
로그인할 때 필요한 `UserDetailsService`의 `loadUserByUsername`함수를 
보시면 반환값이 `UserDetails`인 것을 볼 수 있습니다. 
이렇듯 springsecurity 에서는 하나의 규격화된 `UserDetails`인터페이스를 
상속 받은 클래스를 사용자로 인식하고 인증합니다. 

`User`는 `org.springframework.security.core.userdetails.User`으로 
`User`클래스를 보시면 `UserDetails`가 상속되어 있습니다. 
`UserDetails`를 직접 `SecurityMember`에 상속하여 구현해도 되지만 
`UserDetails는 interface`로 구성되어 있어 모든 함수를 `override`해야합니다. 
그러므로 `User`를 상속받는 방법으로 진행하겠습니다.

`UserDtails`를 구성할 때 `role`을 `Collection<GrantedAuthority>`으로 넘겨줘야합니다. 
그래서 `parseAuthorities`메소드를 만들어 뒀습니다. 
저희는 `role`을 하나만 가지고 있다고 가정하고 파싱하겠습니다.

**MemberService**

인증을 할 때 `UserDetailsService`의 `loadUserByUsername(String username)`로 
`DB`에서 유저정보를 가져오게 됩니다. 
그러므로 `UserDetailsService`를 상속받은 `MemberService`의 
`loadUserByUsername`를 구현합니다.

```java
public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    Member member = memberRepository.
                    findByEmail(email).
                    orElseThrow(() -> new UsernameNotFoundException("Have no registered members"));
            
    return SecurityMember.getMemberDetails(member);
}
```

**JwtFactory**
```java
@Slf4j
@Component
public class JwtFactory {

    private static String SECRET = "TheSecret";

    /*
     * 유저의 권한정보로 토큰을 만듬(claim에는 여러 정보가 올 수 있다.)
     * */
    public String generateToken(SecurityMember securityMember) {
        String token;

        token = JWT.create()
                .withIssuer("yerin")
                .withClaim("EMAIL", securityMember.getUsername())
                .sign(Algorithm.HMAC256(SECRET));

        log.info("token -- "+token);

        return token;

    }

}
```
`JWT token`생성을 위해 `JwtFactory`를 만들어줍니다.

드디어 기본적인 작업이 끝났습니다.👏👏 다음으로는 요청이 들어오는 처음단계인 
`AbstractAuthenticationProcessingFilter`를 구현하겠습니다.

**BasicLoginProcessingFilter**
```java
public class BasicLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    @Autowired
    BasicLoginAuthenticationSuccessHandler successHandler;

    @Autowired
    BasicLoginAuthenticationFailureHandler failureHandler;

    /*
    * todo urlmatcher랑 string 두개의 형식으로 생성자 생성하는거 설명하기
    * */
    public BasicLoginProcessingFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        LoginMemberDto loginMemberDto;
        loginMemberDto = new ObjectMapper().readValue(request.getReader(), LoginMemberDto.class);
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(loginMemberDto.getEmail(),loginMemberDto.getPassword(), Collections.emptyList());

        return this.getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
```
**BasicLoginAuthenticationSuccessHandler**
```java
@Component
public class BasicLoginAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private JwtFactory jwtFactory;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        SecurityMember securityMember = (SecurityMember) authentication.getPrincipal();

        String token = jwtFactory.generateToken(securityMember);

        TokenDto tokenDto = new TokenDto(token);

        makeResponse(response,tokenDto);

    }

    private void makeResponse(HttpServletResponse response, TokenDto tokenDto) throws IOException {

        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.setStatus(HttpStatus.OK.value());
        response.getWriter().write(objectMapper.writeValueAsString(tokenDto));
        //objectMapper.writeValue(response.getWriter(), tokenDto);

    }
}
```
**BasicLoginAuthenticationFailureHandler**
```java
@Component
public class BasicLoginAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Autowired
    ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(exception.getMessage());

    }
}
```




<br></br>
<br></br>
<h1 id="att">❗必부록 </h1>

모른다면 필수로 봐야하는 부록

<h2 id="step3-att">step3-참고 JWT란</h2>

`JWT`란 `Json Web Token`의 약자로 말 그대로 `json`으로 제공하는 토큰입니다.
우리는 올바른 정보를 보내온 회원에게 토큰을 부여하고 추가적인 `api`를 이용할 때 
별다른 로그인 없이 토큰을 통해서 권한을 확인할 수 있습니다.



그러면 `JWT`토큰으로 어떻게 권한을 확인할 수 있을까?



`JWT`의 기본 구조는

* `Header`

* `Payload`

* `Signature`



이렇게 3 부분으로 나뉩니다. 이 3 부분은 `.`으로 구분하여 아래와 같은 형식으로
나타납니다.

`aaaaaaa.bbbbbbb.zzzzzzz` 

`JWT`를 조금 더 살펴보겠습니다.

>Header

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

`Header`에는 암호화 알고리즘(`alg`)과 토큰의 타입(`typ`)으로 구성되어있습니다.

>Payload

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

`Payload`은 `clame`으로 구성되어 있습니다. 여기에 유저의 정보를 담습니다.
주의해야할 점은 개인의 민감한 정보를 `clame`에 담지 않는것 입니다. 

`JWT`토큰은 알고리즘만 알고있다면 해석이 가능함으로 개인정보 유출의 위험이 있습니다.

>Signature

`Signature`은 `Header`,`Payload`값을 인코딩하고 `secret`값으로
해쉬한 암호화 값입니다.

우리가 작성한 코드로 `JWT`를 어떻게 구성하는지 살펴보겠습니다.

```java
String SECRET = "TheSecret";

token = JWT.create()
​                .withIssuer("yerin")
​                .withClaim("EMAIL", email)
​                .sign(Algorithm.HMAC256(SECRET));
```

* `SECRET`은 `Signature` 부분에서 `secret`값으로 사용됩니다.
* `withIssuer`와 `withClaim`은 `Payload`에 기록됩니다. 

이렇게 구성된 `JWT`토큰을 디코딩하여 그 정보를 확인하고 인증합니다.