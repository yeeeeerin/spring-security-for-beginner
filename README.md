# SpringSecurity가 궁금한 히치하이커를 위한 안내서(제작중)
<초보자도(가) 이해하는 SpringSecurity guide>

스프링시큐리티를 처음 공부하시는 여러분을 위한 초보자 가이드 입니다.

* [step1 - 유저 모델링](#step1) 
* [step2 - 회원가입 ](#step2)
* [step3 - 로그인](#step3)
* [step4 - 발급받은 jwt으로 인증](#step4)

<br></br>
**❗[必부록]** 

* [step3-참고 JWT란](#step3-att)
* [filter chain에 관하여](#step3-att2)


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
public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByEmail(String email);

}

```
**MemberService**
```java
@Service
@RequiredArgsConstructor
@Slf4j
public class MemberService implements UserDetailsService {

    private final MemberRepository memberRepository;

    private final PasswordEncoder passwordEncoder;

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

회원정보를 `DB`에 넣을 때, 비밀번호를 암호화 하기위해 `SecurityConfig`파일을 작성 후
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

저는 추가적으로 `h2 DB`에 접근하기 위한 설정을 `SecurityConfig`에 추가적으로 넣어줬습니다.

`HttpSecurity`는 `http`요청에 대해 웹기반 보안기능을 구성할 수 있습니다.
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
@RequiredArgsConstructor
public class AuthController {

    private final MemberService memberService;

    @PostMapping("/signUp")
    public String signUp(@RequestBody Member member){
        memberService.singUp(member);
        return "ok";
    }
}
```

<br></br>

<h2 id="step3">step3 - 로그인</h2>

로그인이 성공하면 `JWT token`을 부여하는 방식으로 진행하겠습니다.

아래는 `login` 요청이 들어왔을 때의 절차 입니다.

1. 요청이 들어오면 `AbstractAuthenticationProcessingFilter`에 들어가게 됩니다.
2. 그 다음 `filter`의 `attemptAuthenticationg`메소드를 통해 유저의
정보가 담긴 `Authentication`객체(인증 전)를 `AuthenticationManager`에 전달합니다.
    * `Authentication`객체는 `UsernamePasswordAuthenticationToken`을 통해
    만듭니다.
3. 내부적으로 `Spring Security`의 `ProviderManager`를 통해 적잘한 
`AuthenticationProvider`를 찾습니다.
4. `AuthenticationProvider`의 `authenticate`메소드로 인증을 진행합니다.
5. 인증에 성공했다면 성공한 `Authentication`객체(인증 후)를 `filter`에 다시 반환해 
`authenticationSuccessHandler`를 수행합니다.
6. `authenticationSuccessHandler`를 통해 `jwt token`을 발급하고 `response`를 채워줍니다.

</br>

먼저 `filter`와 `provider`를 구현하기 전에 몇가지 작업을 해야합니다.

**LoginMemberDto**
```java
@Data
public class LoginMemberDto {
    String email;
    String password;
}
```
단순한 `email`과 `password`를 받는 `dto`입니다.

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
    
    public String getRole(){
            return getAuthorities().stream().findFirst().get().getAuthority();
    }
}
```
회원정보를 가지고 있는 인증객체인 `userdetails`를 구현해야합니다.

>**이미 `Member`라는 유저 객체가 있는데 `UserDetails`는 뭔가요?**

>`UserDetails`는 인증 객체로서 사용자 정보를 저장합니다. 
<--는 `javadoc`에서 발최한 부분으로 더욱 직관적으로 설명하자면 
로그인할 때 필요한 `UserDetailsService`의 `loadUserByUsername`함수를 
보시면 반환값이 `UserDetails`인 것을 볼 수 있습니다. 
이렇듯 `springsecurity` 에서는 하나의 규격화된 `UserDetails`인터페이스를 
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

**JwtSettings**
```java
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "jwt", ignoreInvalidFields = true)
public class JwtSettings {

    private String tokenIssuer;
    private String tokenSigningKey;

}
```
`application.properties`의 `jwt.`으로 시작하는 값들을 가져와 각 변수에 `setting`해줍니다.

>`application.properties` 설정
>```
>jwt.tokenIssuer=yerin
>jwt.tokenSigningKey=abcdefg
>```

**JwtFactory**
```java
@Slf4j
@Component
public class JwtFactory {

    @Autowired
        private JwtSettings jwtSettings;
    
        /*
         * 유저의 권한정보로 토큰을 만듬(claim에는 여러 정보가 올 수 있다.)
         * */
        public String generateToken(SecurityMember securityMember) {
            String token;
    
            token = JWT.create()
                    .withIssuer(jwtSettings.getTokenIssuer())
                    .withClaim("EMAIL", securityMember.getUsername())
                    .withClaim("ROLE",securityMember.getRole())
                    .sign(Algorithm.HMAC256(jwtSettings.getTokenSigningKey()));
    
            log.info("token -- "+token);
    
            return token;
    
        }

}
```
`JWT token`생성을 위해 `JwtFactory`를 만들어줍니다.


드디어 기본적인 작업이 끝났습니다.👏👏 

다음으로는 요청이 들어오는 처음단계인 `AbstractAuthenticationProcessingFilter`를 구현하겠습니다.

>`provider`는 `filter`와 `success,failure handler` 사이에서 동작하지만
`filter`구현에 있어서 마지막으로 `provider`를 작성하도록 하겠습니다.

**BasicLoginProcessingFilter**
```java
public class BasicLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    @Autowired
    private BasicLoginAuthenticationSuccessHandler successHandler;

    @Autowired
    private BasicLoginAuthenticationFailureHandler failureHandler;

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
우리는 필터의 생성자의 파라미터로 `url`을 받습니다.
`url`을 받는 2가지 방법이 있는데 하나는 위의 예제와 같이 `String`으로 받는
방법이 있고 또하나는 `RequestMatcher`로 받는 방법입니다.
>`RequestMatcher`로 받는 경우 `RequestMatcher interface`를 구현하여
`RequestMatcher`에서 미리 정의한 `Request pattern`들로 요청을 판별합니다.

요청이 들어왔다면 `attemptAuthenticationg`메소드를 통해 유저의
정보가 담긴 `Authentication`객체(인증 전)를 
`AuthenticationManager`에 전달합니다.(인증절차 2번의 내용)

여기서 사용하는 `UsernamePasswordAuthenticationToken`으로 `Authentication`객체를
만드는데 `UsernamePasswordAuthenticationToken`의 어떤생성자를 부르느냐에 따라
인증 전 `Authentication`를 만드는지 인증 후 `Authentication`을 만드는지 결정합니다.


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
    }
}
```
인증에 성공했다면 `AuthenticationSuccessHandler`를 통해 토큰값을 주고 맞는 
`response`값을 채워줍니다.

**BasicLoginAuthenticationFailureHandler**
```java
@Component
public class BasicLoginAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(exception.getMessage());
    }
}
```

인증에 실패했다면 `AuthenticationFailureHandler`를 통해 실패했다는 `response`값을
채워줍니다.

이제 마지막으로 `provider`를 만들어 주겠습니다.

```java
public class BasicLoginSecurityProvider implements AuthenticationProvider {

    @Autowired
    private MemberService memberService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        SecurityMember member = (SecurityMember) memberService.loadUserByUsername(email);

        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new BadCredentialsException("password is incorrect");
        }

        return new UsernamePasswordAuthenticationToken(member, password, member.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```
`AuthenticationProvider`를 상속받으면 `authenticate`와 `supports`메소드를 구현해야합니다.
* `authenticate`에서 `userdetailservice`의 `loadUserByUsername(String username)`으로부터
유저정보를 가져와 올바른 인증을 하게됩니다.
* `supports`는 이 `AuthenticationProvider`가 표시된 `Authentication`객체를 지원하는 경우 `true`를 반환합니다. 

이제 정말 **마지막**으로 `SecurityConfig`에 등록하면 됩니다. 

`filter`를 등록하기 전에 `filter`에 관하여 간락하게 설명하겠습니다.

`Spring security`는 약 10가지의 필터를 순회하여 알맞은 응답값을 찾습니다.
이 10가지 필터는 `security`에서 기존에 정해놓은 `filter`들로서 만약 우리가 위의
로그인과같이 `filter`를 커스텀한다면 `spring security`의 `filterChainProxy`에
등록을 시켜주어야합니다.

그 방법으로는 두가지 방법이 있습니다.
1.  기본 `tomcat`의 필터에 등록하기
2.  `spring sececurity`에 등록하기

>`filter`를 등록하기 전에 `filter`에 관하여 간락하게 설명하겠습니다.

>`Spring security`는 약 10가지의 필터를 순회하여 알맞은 응답값을 찾습니다.
이 10가지 필터는 `security`에서 기존에 정해놓은 `filter`들로서 만약 우리가 위의
로그인과같이 `filter`를 커스텀한다면 spring `security`의 `filterChainProxy`에
등록을 시켜주어야합니다.

>그 방법으로는 두가지 방법이 있습니다.
>1.  기본 `tomcat`의 필터에 등록하기
>2.  `spring sececurity`에 등록하기
>>>>>>> step3

🔐** FilterChainProxy 中 **
```java
@Override
		public void doFilter(ServletRequest request, ServletResponse response)
				throws IOException, ServletException {
			if (currentPosition == size) {
				if (logger.isDebugEnabled()) {
					logger.debug(UrlUtils.buildRequestUrl(firewalledRequest)
							+ " reached end of additional filter chain; proceeding with original chain");
				}

				// Deactivate path stripping as we exit the security filter chain
				this.firewalledRequest.reset();

                //기존 필터 순회
				originalChain.doFilter(request, response);
			}
			else {
				currentPosition++;

				Filter nextFilter = additionalFilters.get(currentPosition - 1);

				if (logger.isDebugEnabled()) {
					logger.debug(UrlUtils.buildRequestUrl(firewalledRequest)
							+ " at position " + currentPosition + " of " + size
							+ " in additional filter chain; firing Filter: '"
							+ nextFilter.getClass().getSimpleName() + "'");
				}

                //spring security 필터 순회
				nextFilter.doFilter(request, response, this);
			}
		}
```

위의 코드를 보면 `originalChain.doFilter(request, response);` 와
`nextFilter.doFilter(request, response, this);`를 보실 수 있습니다.
`originalChain.doFilter(request, response);`은 기본 `tomcat`에 등록된 
기본적인 `filter`들이 돌아가고
`nextFilter.doFilter(request, response, this);`는 `spring security`에
사용되는 `filter`들이 돌아갑니다.

`filter`가 작동되는 순서는 아주 중요하며 순서가 바뀌었을 시 그 결과값도 바뀔 수 있음으로
`filter`를 `nextFilter`에서 돌아가도록 해주어야합니다. 

그 방법으로는 `configure(HttpSecurity http)`에 
`addFilterBefore(basicLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)`
를 추가해 주는 것입니다.


>위의 코드를 보면 `originalChain.doFilter(request, response);` 와
`nextFilter.doFilter(request, response, this);`를 보실 수 있습니다.
`originalChain.doFilter(request, response);`은 기본 `tomcat`에 등록된 
기본적인 `filte`r들이 돌아가고
`nextFilter.doFilter(request, response, this);`는 `spring security`에
사용되는 `filter`들이 돌아갑니다.

>`filter`가 작동되는 순서는 아주 중요하며 순서가 바뀌었을 시 그 결과값도 바뀔 수 있음으로
`filter`를 `nextFilter`에서 돌아가도록 해주어야합니다. 

>그 방법으로는 `configure(HttpSecurity http)`에 
`addFilterBefore(basicLoginProcessingFilter()`, `UsernamePasswordAuthenticationFilter.class)`
를 추가해 주는 것입니다.



**SecurityConfig**
```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {



    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .headers().frameOptions().disable();
        http
                .csrf().disable();
        http
                .authorizeRequests()
                .antMatchers("/h2-console/**").permitAll();
        http
                .addFilterBefore(basicLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtLoginProcessingFilter(),UsernamePasswordAuthenticationFilter.class);

    }

    @Bean
    public BasicLoginSecurityProvider basicLoginSecurityProvider(){
        return new BasicLoginSecurityProvider();

    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider(){
        return new JwtAuthenticationProvider();
    }

    @Bean
    protected BasicLoginProcessingFilter basicLoginProcessingFilter() throws Exception {
        BasicLoginProcessingFilter filter = new BasicLoginProcessingFilter("/login");
        filter.setAuthenticationManager(super.authenticationManagerBean());
        return filter;
    }

    @Bean
    protected JwtLoginProcessingFilter jwtLoginProcessingFilter() throws Exception{
        FilterSkipPathMatcher matchar = new FilterSkipPathMatcher(Arrays.asList("/login","/signUp"), "/**");
        JwtLoginProcessingFilter filter = new JwtLoginProcessingFilter(matchar);
        filter.setAuthenticationManager(super.authenticationManagerBean());
        return filter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth
                .authenticationProvider(basicLoginSecurityProvider())
                .authenticationProvider(jwtAuthenticationProvider());

    }

}
```

그리고 `provider`를 주입받고 `AuthenticationManagerBuilder`를 통해
`provider`를 등록합니다.

성공했다면 이러한 결과값을
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5ZXJpbiIsIkVNQUlMIjoieWVyaW5AeWVyaW4uY29tIn0.G2W_yQ7FQzmT8h6r7rOLHd_IBuW4fGV8SkfYr-6QKtc"
}
Response code: 200; Time: 601ms; Content length: 148 bytes
```

실패했다면 이러한 결과값을 볼 수 있습니다.
```json
//비밀번호 틀렸을 시
password is incorrect

//회원이 등록되어있지 않았을 시
Have no registered members

Response code: 401; Time: 114ms; Content length: 21 bytes
```

<br></br>

<h2 id="step4">step4 - 발급받은 jwt으로 로그인</h2>

step3에서 발급받은 `jwt token`으로 인증을 시도해보겠습니다.

절차는 로그인과 비슷함으로 내부적인 동작은 생략한 절차입니다.

1. 요청이 들어오면 `AbstractAuthenticationProcessingFilter`에 들어가게 됩니다.
2. 그 다음 `filter`의 `attemptAuthenticationg`메소드를 통해 `header`에 있는 
`token`값을 분리해 가져와 `Authentication`객체(인증 전)에 담고 `manager`에 전달합니다.
3. `AuthenticationProvider`의 `authenticate`메소드로 `token`에 담겨있는
인증정보를 확인하여 인증을 진행합니다.
4. 인증에 성공했다면 `authenticationSuccessHandler`를 통해 `SecurityContext`를 
생성하고 `SecurityContextHolder`에 보관합니다.

이번 step에도 `filter`를 구현하기 전에 몇가지 사전 작업을 진행하겠습니다.

**FilterSkipMatcher**
```java
public class FilterSkipPathMatcher implements RequestMatcher {

    private OrRequestMatcher orRequestMatcher;
    private RequestMatcher requestMatcher;

    public FilterSkipPathMatcher(List<String> pathsToSkip, String processingPath) {

        //건너띌 주소 묶음
        this.orRequestMatcher = new OrRequestMatcher(
                pathsToSkip.stream()
                        .map(AntPathRequestMatcher::new)
                        .collect(Collectors.toList())
        );

        //인증을 진행할 주소
        this.requestMatcher = new AntPathRequestMatcher(processingPath);
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return !orRequestMatcher.matches(request) && requestMatcher.matches(request);
    }
}
```
`spring security`는 모든 요청에 대해 `manager`에 등록된 모든 필터를 돌게됩니다.
그런데 우리는 `jwt token`을 이용하여 게시물 정보를 얻는다던가 유저의 프로필 정보를 얻는다던가
하는 여러 `api`을 사용해야합니다. 유저의 `email,password`로 로그인을 할 때는 
`filter`에 `"/login"`이라는 요청하나만 적용하면 되서 생성자를 통해 `string` 타입으로 요청을 받고
그 요청에만 `filter`를 적용할 수 있게 해주었습니다.

그럼 여러 `filter`의 요청을 `"/**"`라고 하게되면 `/login`요청에도 `jwt`인증 `filter`가 돌게 되는데
`/login`요청에는 아직 `token`이 부여받지 않는 상태라 에러가 나게 됩니다. 이 문제를 해결하기 위해서는 어떻게 해야할까요?

우리는 그 방법으로 step3 `filter`구현 부분에서 잠깐 설명한 `RequestMatcher`를 이용할 것입니다. 
바로 위의 `FilterSkipMatcher`가 `RequestMatcher`를 이용하여 `filter`를 거치지 않을 `url`을 걸러
주는 역할을 합니다.
 
`ReqestMatcher`에는 여러 `Request pattern`들이 있습니다. [request pattern 보러가기](https://docs.spring.io/spring-security/site/docs/4.2.10.RELEASE/apidocs/org/springframework/security/web/util/matcher/RequestMatcher.html)
그 중 우리가 사용하는 `OrRequestMatcher`는 여러 요청을 `List<String>`형식으로 저장할 수 있는 `RequestMatcher`이며
`AntPathRequestMatcher`는 `"/books/**"`와 같이 `ant pattern`을 저장할 수 있는 `RequestMatcher`입니다.

**JwtTokenExtractor**
```java
@Component
public class JwtTokenExtractor {
    public static final String HEADER_PREFIX = "Bearer ";

    public String extract(final String header) {
        if (StringUtils.isEmpty(header)) {
            throw new AuthenticationServiceException("Authorization header가 없습니다.");
        }

        if (header.length() < HEADER_PREFIX.length()) {
            throw new AuthenticationServiceException("authorization header size가 옳지 않습니다.");
        }

        if (!header.startsWith(HEADER_PREFIX)) {
            throw new AuthenticationServiceException("올바른 header형식이 아닙니다.");
        }

        return header.substring(HEADER_PREFIX.length());
    }
}
```
`jwt token`은 `header`에 `Authorization: Bearer aaa.bbb.ccc`이런식으로 담겨옵니다.
우리는 `aaa.bbb.ccc`이 부분만 가져올 수 있도록하는 `JwtTokenExtractor`만듭니다.
여기서는 `header`값이 이상한 값이 들어왔는지 간단한 검사 작업도 진행합니다.

다음으로 `filter`와 `provider`를 구현하겠습니다.

**JwtLoginProcessingFilter**
```java
public class JwtLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    @Autowired
    JwtTokenExtractor tokenExtractor;


    public JwtLoginProcessingFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String tokenPayload = request.getHeader("Authorization");

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(this.tokenExtractor.extract(tokenPayload),null);

        return super.getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        //인증에 성공한 경우 해당 사용자에게 권한을 할당
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        //context를 만들고 보관
        SecurityContextHolder.setContext(context);
        //남을 필터들에 대해 다 돌음 (필터를 선택해서 돌수도 있다)
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        getFailureHandler().onAuthenticationFailure(request, response, failed);

    }
}
```
기본적으로 `step3`과 비슷하지만 각 `handler`를 따로 구현하지 않았다는 점과
`successfulAuthentication`에 `SecurityContext`를 생성해준 점이 추가 되었습니다.

**JwtAuthenticationProvider**
```java
@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    JwtFactory jwtFactory;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = (String) authentication.getPrincipal();
        SecurityMember member = jwtFactory.decodeToken(token);
        return new UsernamePasswordAuthenticationToken(member, member.getPassword(), member.getAuthorities());

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```
`provider`에서 인증은 `token`을 분석하여 인증후 객체를 만듭니다.

**SecurityConfig**
```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    BasicLoginSecurityProvider basicLoginSecurityProvider;

    //1. provider 주입받기
    @Autowired
    JwtAuthenticationProvider jwtAuthenticationProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .headers().frameOptions().disable();
        http
                .csrf().disable();
        http
                .authorizeRequests()
                .antMatchers("/h2-console/**").permitAll();
        http
                .addFilterBefore(basicLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                //3. filter등록하기
                .addFilterBefore(jwtLoginProcessingFilter(),UsernamePasswordAuthenticationFilter.class);
    }

    protected BasicLoginProcessingFilter basicLoginProcessingFilter() throws Exception {
        BasicLoginProcessingFilter filter = new BasicLoginProcessingFilter("/login");
        filter.setAuthenticationManager(super.authenticationManagerBean());
        return filter;
    }

    //2. filter 선언하기
    protected JwtLoginProcessingFilter jwtLoginProcessingFilter() throws Exception{
        FilterSkipPathMatcher matchar = new FilterSkipPathMatcher(Arrays.asList("/login","/signUp"), "/**");
        JwtLoginProcessingFilter filter = new JwtLoginProcessingFilter(matchar);
        filter.setAuthenticationManager(super.authenticationManagerBean());
        return filter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth
                .authenticationProvider(this.basicLoginSecurityProvider)
                //4. provider등록하기
                .authenticationProvider(this.jwtAuthenticationProvider);
    }
    
}
```

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

    @GetMapping("/only_user")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String onlyUser(){
        return "hi user";
    }

    @GetMapping("/only_admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String onlyAdmin(){
        return "hi admin";
    }
}
```

###실행결과
```json
GET http://localhost:8080/only_user
Authorization: Bearer aaaa.bbbb.cccc
```
`login`해서 받은 토큰값으로 접근을하면

```json
Content-Type: text/plain;charset=UTF-8
Content-Length: 7
Date: Wed, 27 Feb 2019 08:02:58 GMT

hi user

Response code: 200; Time: 91ms; Content length: 7 bytes
```

와 같은 실행 결과를 받을 수 있습니다.

`/only_admin`은 따로 실행해보시길바랍니다


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

<h2 id="step3-att2">filter에 관하여(작성중)</h2>


우리는 지금까지 

addFilterBefore를 통해서 필터 등록하기
filter에 @Bean을 붙여 등록하기

@Bean으로 등록했다면 프로젝트가 처음 시작할 때 @Bean검사를 하게되면서 ApplicationFilterChain에 자동 등록되어서 돌아가는데
o.s.security.web.FilterChainProxy에는 등록이 안되어서 로그에 안찍힌거임
