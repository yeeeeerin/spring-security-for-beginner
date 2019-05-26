package com.example.springsecurityguide.Service;


import com.example.springsecurityguide.domain.Member;
import com.example.springsecurityguide.domain.MemberRole;
import com.example.springsecurityguide.domain.SecurityMember;
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

import java.util.Optional;

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

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Member member = memberRepository.
                findByEmail(email).
                orElseThrow(() -> new UsernameNotFoundException("Have no registered members"));

        return SecurityMember.getMemberDetails(member);
    }

}
