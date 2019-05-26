package com.example.springsecurityguide.Service;


import com.example.springsecurityguide.domain.Member;
import com.example.springsecurityguide.domain.MemberRole;
import com.example.springsecurityguide.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
